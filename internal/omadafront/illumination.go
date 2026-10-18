package omadafront

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
)

// IlluminationControls changes persistent source lighting policy, independently
// of the bounded preview override provided by OutputControls.WhiteLight.
type IlluminationControls interface {
	// Capabilities returns explicitly configured native modes without network I/O.
	Capabilities() IlluminationCapability
	// Settings reads the source policy; an unmapped policy has an empty Mode.
	Settings(context.Context) (IlluminationSettings, error)
	// Set validates and applies one change, preserving omitted fields. It must
	// return success only after source acceptance and verified readback.
	Set(context.Context, IlluminationChange) error
}

// IlluminationCapability lists supported native pre-night mode values. The NVR
// uses fixed menu choices, so unlisted choices are still rejected on write.
type IlluminationCapability struct {
	Modes               []string
	Brightness          bool
	AutomaticBrightness bool
}

// IlluminationSettings is a source readback. Empty Mode means the current source
// policy has no verified native equivalent. Brightness is a percentage, and
// AutomaticBrightness distinguishes automatic intensity from a manual setting.
type IlluminationSettings struct {
	Mode                string
	Brightness          int
	AutomaticBrightness bool
}

// IlluminationChange contains validated native fields. Empty Mode and nil
// pointers preserve the corresponding source settings; no timer is implied.
type IlluminationChange struct {
	Mode                string
	Brightness          *int
	AutomaticBrightness *bool
}

// illuminationCapability filters configuration to the known native vocabulary.
func (s *Server) illuminationCapability() IlluminationCapability {
	if s.illumination == nil {
		return IlluminationCapability{}
	}
	capability := s.illumination.Capabilities()
	filtered := []string{}
	for _, mode := range capability.Modes {
		if validIlluminationMode(mode) && !slices.Contains(filtered, mode) {
			filtered = append(filtered, mode)
		}
	}
	if len(filtered) == 0 {
		return IlluminationCapability{}
	}
	capability.Modes = filtered
	return capability
}

// validIlluminationMode recognizes shipped native image policy values, without
// assuming that the configured physical source supports any particular value.
func validIlluminationMode(mode string) bool {
	switch mode {
	case "white_led_always_on", "auto_color", "auto_ir", "ir_always_on", "human_triggered_color", "off":
		return true
	default:
		return false
	}
}

// illuminationRead reports only live source settings and supported capabilities.
// Failed image reads never fall back to a fabricated persistent lighting mode.
func (s *Server) illuminationRead(module, name string) (any, bool) {
	capability := s.illuminationCapability()
	if len(capability.Modes) == 0 {
		return nil, false
	}
	if module == "image_capability" {
		switch name {
		case "supplement_lamp":
			lamps := []string{}
			if slices.Contains(capability.Modes, "auto_ir") || slices.Contains(capability.Modes, "ir_always_on") || slices.Contains(capability.Modes, "human_triggered_color") {
				lamps = append(lamps, "infrared_lamp")
			}
			if slices.Contains(capability.Modes, "auto_color") || slices.Contains(capability.Modes, "white_led_always_on") || slices.Contains(capability.Modes, "human_triggered_color") || capability.Brightness || s.outputCapability().WhiteLight {
				lamps = append(lamps, "white_lamp")
			}
			if len(lamps) == 0 {
				return nil, false
			}
			fields := map[string]any{"supplement_lamp_type": lamps, "support_pre_night_vision_mode_version": "1.0"}
			if s.outputCapability().WhiteLight {
				fields["white_light_manual_version"] = "1.0"
			}
			return fields, true
		case "smart_white_lamp":
			if capability.Brightness {
				return map[string]any{"smart_white_lamp_supported": "1", "smartwtl_digital_level_supported": "1"}, true
			}
		}
		return nil, false
	}
	if module != "image" || (name != "switch" && name != "common") {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), outputCallTimeout)
	defer cancel()
	settings, err := s.illumination.Settings(ctx)
	if err != nil || (settings.Mode != "" && !slices.Contains(capability.Modes, settings.Mode)) || settings.Brightness < 0 || settings.Brightness > 100 {
		return nil, false
	}
	if name == "switch" {
		value, _ := s.virtualImaging.read("image", "switch")
		fields := value.(map[string]any)
		fields["switch_mode"] = "common"
		if settings.Mode != "" {
			fields["pre_night_vision_mode"] = settings.Mode
		}
		if mode := illuminationNightMode(settings.Mode); mode != "" {
			fields["night_vision_mode"] = mode
		}
		return fields, true
	}
	if !capability.Brightness {
		return nil, false
	}
	mode := "manual"
	if settings.AutomaticBrightness {
		mode = "auto_wtl"
	}
	return map[string]any{"smartwtl": mode, "smartwtl_digital_level": strconv.Itoa(settings.Brightness)}, true
}

// illuminationNightMode maps a supported preset to the native legacy lamp type.
func illuminationNightMode(mode string) string {
	switch mode {
	case "white_led_always_on", "auto_color":
		return "wtl_night_vision"
	case "auto_ir", "ir_always_on":
		return "inf_night_vision"
	case "human_triggered_color":
		return "md_night_vision"
	default:
		return ""
	}
}

// illuminationRequest validates the entire image/video batch before source I/O.
// Virtual flicker/rate changes are committed only after the physical write succeeds.
func (s *Server) illuminationRequest(ctx context.Context, method string, request map[string]json.RawMessage) (map[string]any, bool) {
	if s.illumination == nil || method != "set" || request["image"] == nil {
		return nil, false
	}
	change, virtual, valid := s.illuminationChange(request)
	if !valid {
		return map[string]any{"error_code": unsupportedCode}, true
	}
	if change.Mode == "" && change.Brightness == nil && change.AutomaticBrightness == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, outputCallTimeout)
	defer cancel()
	if err := s.illumination.Set(ctx, change); err != nil {
		return outputResult(err), true
	}
	if len(virtual) > 1 {
		s.virtualImaging.write("set", virtual)
	}
	return map[string]any{"error_code": 0}, true
}

// illuminationChange accepts only the unified profile and existing virtual
// settings. Unknown fields, unsupported modes and malformed values reject all.
func (s *Server) illuminationChange(request map[string]json.RawMessage) (IlluminationChange, map[string]json.RawMessage, bool) {
	change := IlluminationChange{}
	virtual := map[string]json.RawMessage{"method": json.RawMessage(`"set"`)}
	capability := s.illuminationCapability()
	if len(request) < 2 || len(request) > 3 {
		return change, nil, false
	}
	for module, raw := range request {
		switch module {
		case "method":
			continue
		case "video":
			value, ok := imagingSetting(raw, "common", "sensor_framerate")
			if !ok || (value != "25" && value != "30") {
				return change, nil, false
			}
			virtual[module] = raw
		case "image":
			var sections map[string]json.RawMessage
			if json.Unmarshal(raw, &sections) != nil || len(sections) == 0 || len(sections) > 2 {
				return change, nil, false
			}
			for section, rawFields := range sections {
				var fields map[string]json.RawMessage
				if (section != "switch" && section != "common") || json.Unmarshal(rawFields, &fields) != nil || len(fields) == 0 {
					return change, nil, false
				}
				for field, rawValue := range fields {
					var value string
					if json.Unmarshal(rawValue, &value) != nil || value == "" {
						return change, nil, false
					}
					switch {
					case section == "switch" && field == "flicker" && (value == "50hz" || value == "60hz"):
						// The fixed string-only structure has no unsupported JSON values.
						virtual["image"], _ = json.Marshal(map[string]any{"switch": map[string]string{"flicker": value}})
					case section == "switch" && field == "pre_night_vision_mode" && slices.Contains(capability.Modes, value):
						change.Mode = value
					case section == "common" && field == "smartwtl" && capability.Brightness && (value == "manual" || (value == "auto_wtl" && capability.AutomaticBrightness)):
						automatic := value == "auto_wtl"
						change.AutomaticBrightness = &automatic
					case section == "common" && field == "smartwtl_digital_level" && capability.Brightness:
						brightness, err := strconv.Atoi(value)
						if err != nil || brightness < 0 || brightness > 100 || strconv.Itoa(brightness) != value {
							return change, nil, false
						}
						change.Brightness = &brightness
					default:
						return change, nil, false
					}
				}
			}
		default:
			return change, nil, false
		}
	}
	if change.AutomaticBrightness != nil && ((change.Mode == "white_led_always_on" && *change.AutomaticBrightness) || (change.Mode == "auto_color" && !*change.AutomaticBrightness)) {
		return change, nil, false
	}
	return change, virtual, true
}
