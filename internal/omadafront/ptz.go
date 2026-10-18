package omadafront

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"
)

// PTZ moves the physical lens behind this virtual camera. Move and Stop must
// return without network I/O; the other calls are bounded by their context.
type PTZ interface {
	Capability(context.Context) (PTZCapability, error)
	Move(pan, tilt, zoom float64)
	Stop()
	Presets(context.Context) ([]PTZPreset, error)
	GotoPreset(context.Context, int) error
	// SetPreset stores the current position; id 0 lets the camera choose.
	SetPreset(ctx context.Context, id int, name string) (int, error)
	RemovePreset(context.Context, int) error
}

// PTZCapability is what the source lens actually supports.
type PTZCapability struct {
	PanTilt, Zoom bool
	MaxPresets    int
	Home          bool
}

// PTZPreset is one stored source position with a recorder-facing number.
type PTZPreset struct {
	ID   int
	Name string
}

// ptzSpeedSteps is the recorder UI's speed scale (default 4); a step is
// converted to a normalized ONVIF velocity.
const ptzSpeedSteps = 7

const ptzCallTimeout = 4 * time.Second

// ptzModules are the module names the recorder or camera firmware uses for
// pan/tilt, presets and tours.
var ptzModules = map[string]bool{"ptz": true, "preset": true, "motor": true, "tour": true}

func isPTZRequest(request map[string]json.RawMessage) bool {
	for module := range request {
		if ptzModules[module] {
			return true
		}
	}
	return false
}

// ptzCapabilityFields answers the recorder UI's PTZ capability vocabulary.
// Only movement and presets the source supports are reported.
func (s *Server) ptzCapabilityFields(ctx context.Context) (map[string]any, bool) {
	capability, err := s.ptz.Capability(ctx)
	if err != nil {
		return nil, false
	}
	flag := func(value bool) string {
		if value {
			return "1"
		}
		return "0"
	}
	return map[string]any{
		"zoom_supported": flag(capability.Zoom), "preset_supported": flag(capability.MaxPresets > 0),
		"preset_number_max": strconv.Itoa(capability.MaxPresets),
		"tour_supported":    "0", "pattern_supported": "0", "calibrate_supported": "0", "high_speed_dome": "0",
		"aperture_supported": "0", "focus_supported": "0", "pan_tilt_rotate_sync_supported": "0",
	}, true
}

// ptzRequest handles one PTZ operation. It reports false for shapes it does
// not know, which the caller answers as unsupported and logs by name.
func (s *Server) ptzRequest(ctx context.Context, method string, request map[string]json.RawMessage) (map[string]any, bool) {
	if s.ptz == nil || method != "do" || len(request) != 2 {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, ptzCallTimeout)
	defer cancel()
	for module, raw := range request {
		if module == "method" {
			continue
		}
		var operations map[string]json.RawMessage
		if json.Unmarshal(raw, &operations) != nil || len(operations) != 1 {
			return nil, false
		}
		for operation, body := range operations {
			var fields map[string]json.RawMessage
			if json.Unmarshal(body, &fields) != nil {
				return nil, false
			}
			return s.ptzOperation(ctx, module+"."+operation, fields)
		}
	}
	return nil, false
}

func (s *Server) ptzOperation(ctx context.Context, operation string, fields map[string]json.RawMessage) (map[string]any, bool) {
	ok := map[string]any{"error_code": 0}
	switch operation {
	case "ptz.get_ptz_capability":
		capability, found := s.ptzCapabilityFields(ctx)
		if !found {
			return map[string]any{"error_code": unsupportedCode}, true
		}
		return map[string]any{"ptz_capability": capability, "error_code": 0}, true
	case "ptz.move":
		direction, found := jsonInteger(fields["direction"], 0, 17)
		if !found {
			return nil, false
		}
		speed := float64(4)
		if raw, exists := fields["speed"]; exists {
			speed, found = jsonNumber(raw)
			if !found || speed < 1 || speed > ptzSpeedSteps {
				return nil, false
			}
		}
		return s.ptzDirection(direction, speed)
	case "ptz.continuous_move":
		var velocity [3]float64
		found := false
		for index, name := range []string{"velocity_pan", "velocity_tilt", "velocity_zoom"} {
			if raw, exists := fields[name]; exists {
				number, valid := jsonNumber(raw)
				if !valid || number < -1 || number > 1 {
					return nil, false
				}
				velocity[index], found = number, true
			}
		}
		if !found {
			return nil, false
		}
		s.ptz.Move(velocity[0], velocity[1], velocity[2])
		return ok, true
	case "ptz.stop", "ptz.stop_move", "motor.stop":
		s.ptz.Stop()
		return ok, true
	case "preset.get_preset":
		// This is the camera-native paged API, not the recorder UI's
		// ptz.get_preset API. Its response has a different nested structure;
		// never acknowledge it with the UI array while its contract is absent.
		return map[string]any{"error_code": unsupportedCode}, true
	case "ptz.get_preset":
		presets, err := s.ptz.Presets(ctx)
		if err != nil {
			return map[string]any{"error_code": unsupportedCode}, true
		}
		rows := make([]any, 0, len(presets))
		for _, preset := range presets {
			rows = append(rows, map[string]any{"preset_id": preset.ID, "name": preset.Name})
		}
		return map[string]any{"preset": rows, "error_code": 0}, true
	case "ptz.opt_preset":
		return s.ptzPresetOperation(ctx, fields)
	case "preset.goto_preset":
		id, found := jsonInteger(fields["id"], 1, 65535)
		if !found {
			return nil, false
		}
		return s.ptzResult(s.ptz.GotoPreset(ctx, id)), true
	case "preset.set_preset":
		id, name, valid := presetFields(fields, "id", "name")
		if !valid {
			return nil, false
		}
		_, err := s.ptz.SetPreset(ctx, id, name)
		return s.ptzResult(err), true
	case "preset.remove_preset":
		ids := jsonPresetIDs(fields["id"])
		if len(ids) == 0 {
			return nil, false
		}
		for _, id := range ids {
			if err := s.ptz.RemovePreset(ctx, id); err != nil {
				return s.ptzResult(err), true
			}
		}
		return ok, true
	}
	return nil, false
}

// ptzDirection maps the recorder UI's direction codes: 0 stop, 1 right,
// 2 right-down, 3 down, 4 left-down, 5 left, 6 left-up, 7 up, 8 right-up,
// 10 zoom in, 11 zoom out, 14 focus stop. Scan, focus, reset and aperture
// (9, 12, 13, 15, 16, 17) are not supported by the source.
func (s *Server) ptzDirection(direction int, speed float64) (map[string]any, bool) {
	v := math.Max(0.15, math.Min(1, speed/ptzSpeedSteps))
	moves := map[int][3]float64{1: {v, 0, 0}, 2: {v, -v, 0}, 3: {0, -v, 0}, 4: {-v, -v, 0}, 5: {-v, 0, 0},
		6: {-v, v, 0}, 7: {0, v, 0}, 8: {v, v, 0}, 10: {0, 0, v}, 11: {0, 0, -v}}
	if direction == 0 || direction == 14 {
		s.ptz.Stop()
		return map[string]any{"error_code": 0}, true
	}
	move, found := moves[direction]
	if !found {
		return map[string]any{"error_code": unsupportedCode}, true
	}
	s.ptz.Move(move[0], move[1], move[2])
	return map[string]any{"error_code": 0}, true
}

// ptzPresetOperation follows the recorder UI's opt_type codes: 0 save
// (preset_name, preset_id optional), 1 delete one, 2 go to, 5 delete a list.
func (s *Server) ptzPresetOperation(ctx context.Context, fields map[string]json.RawMessage) (map[string]any, bool) {
	kind, found := jsonInteger(fields["opt_type"], 0, 5)
	if !found {
		return nil, false
	}
	switch kind {
	case 0:
		id, name, valid := presetFields(fields, "preset_id", "preset_name")
		if !valid {
			return nil, false
		}
		saved, err := s.ptz.SetPreset(ctx, id, name)
		if err != nil {
			return s.ptzResult(err), true
		}
		return map[string]any{"preset_id": saved, "error_code": 0}, true
	case 1:
		id, valid := jsonInteger(fields["preset_id"], 1, 65535)
		if !valid {
			return nil, false
		}
		return s.ptzResult(s.ptz.RemovePreset(ctx, id)), true
	case 2:
		id, valid := jsonInteger(fields["preset_id"], 1, 65535)
		if !valid {
			return nil, false
		}
		return s.ptzResult(s.ptz.GotoPreset(ctx, id)), true
	case 5:
		ids := jsonPresetIDs(fields["preset_id_list"])
		if len(ids) == 0 {
			return nil, false
		}
		for _, id := range ids {
			if err := s.ptz.RemovePreset(ctx, id); err != nil {
				return s.ptzResult(err), true
			}
		}
		return map[string]any{"error_code": 0}, true
	}
	return nil, false
}

func (s *Server) ptzResult(err error) map[string]any {
	if err != nil {
		return map[string]any{"error_code": unsupportedCode}
	}
	return map[string]any{"error_code": 0}
}

// jsonNumber accepts a JSON number or a numeric string, as both forms occur
// in recorder requests.
func jsonNumber(raw json.RawMessage) (float64, bool) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, false
	}
	var number float64
	if json.Unmarshal(raw, &number) == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
		return number, true
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return 0, false
	}
	number, err := strconv.ParseFloat(text, 64)
	return number, err == nil && !math.IsNaN(number) && !math.IsInf(number, 0)
}

func jsonInteger(raw json.RawMessage, min, max int) (int, bool) {
	number, valid := jsonNumber(raw)
	if !valid || number < float64(min) || number > float64(max) || number != math.Trunc(number) {
		return 0, false
	}
	return int(number), true
}

// presetFields distinguishes an omitted, camera-selected ID from an invalid
// supplied ID. A malformed body must not become a request to create a preset.
func presetFields(fields map[string]json.RawMessage, idKey, nameKey string) (int, string, bool) {
	if fields == nil {
		return 0, "", false
	}
	id := 0
	if raw, exists := fields[idKey]; exists {
		var valid bool
		id, valid = jsonInteger(raw, 0, 65535)
		if !valid {
			return 0, "", false
		}
	}
	var name string
	if raw, exists := fields[nameKey]; exists {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &name) != nil {
			return 0, "", false
		}
	}
	return id, name, true
}

// jsonPresetIDs validates the complete bounded list before any preset can be
// deleted. A single number or numeric string is also accepted.
func jsonPresetIDs(raw json.RawMessage) []int {
	if number, ok := jsonInteger(raw, 1, 65535); ok {
		return []int{number}
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) > 256 {
		return nil
	}
	result := make([]int, 0, len(values))
	for _, value := range values {
		number, valid := jsonInteger(value, 1, 65535)
		if !valid {
			return nil
		}
		result = append(result, number)
	}
	return result
}
