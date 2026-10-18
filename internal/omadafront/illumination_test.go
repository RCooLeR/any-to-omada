package omadafront

import (
	"context"
	"errors"
	"testing"
)

// fakeIllumination records source commands and supplies independently mutable
// readback, so tests do not confuse a frontend selection with hardware state.
type fakeIllumination struct {
	capability IlluminationCapability
	settings   IlluminationSettings
	changes    []IlluminationChange
	readCalls  int
	fail       bool
}

// Capabilities returns the explicit fixture policies.
func (f *fakeIllumination) Capabilities() IlluminationCapability { return f.capability }

// Settings reads fixture state or exposes a source failure to the adapter.
func (f *fakeIllumination) Settings(context.Context) (IlluminationSettings, error) {
	f.readCalls++
	if f.fail {
		return IlluminationSettings{}, errors.New("source-private-detail")
	}
	return f.settings, nil
}

// Set records an attempted change and only updates the fixture on source success.
func (f *fakeIllumination) Set(_ context.Context, change IlluminationChange) error {
	f.changes = append(f.changes, change)
	if f.fail {
		return errors.New("source-private-detail")
	}
	if change.Mode != "" {
		f.settings.Mode = change.Mode
	}
	if change.Brightness != nil {
		f.settings.Brightness = *change.Brightness
	}
	if change.AutomaticBrightness != nil {
		f.settings.AutomaticBrightness = *change.AutomaticBrightness
	}
	return nil
}

func TestNativeIlluminationUsesPersistentSourceReadback(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			illumination := &fakeIllumination{
				capability: IlluminationCapability{Modes: []string{"white_led_always_on", "auto_color", "auto_ir"}, Brightness: true, AutomaticBrightness: true},
				settings:   IlluminationSettings{Mode: "auto_ir", Brightness: 70, AutomaticBrightness: true},
			}
			outputs := &fakeOutputs{capability: OutputCapability{WhiteLight: true}}
			s := testServer(t, func(cfg *Config) { cfg.Illumination, cfg.Outputs = illumination, outputs })
			send := outputTransport(t, s, transport)
			value := send(`{"method":"get","image_capability":{"name":"supplement_lamp"}}`)
			capability := value["image_capability"].(map[string]any)["supplement_lamp"].(map[string]any)
			if capability["support_pre_night_vision_mode_version"] != "1.0" || capability["white_light_manual_version"] != "1.0" {
				t.Fatalf("persistent and bounded lamp offers did not coexist: %v", value)
			}
			value = send(`{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on","flicker":"60hz"},"common":{"smartwtl":"manual","smartwtl_digital_level":"42"}},"video":{"common":{"sensor_framerate":"30"}}}`)
			if value["error_code"] != float64(0) || len(illumination.changes) != 1 || len(outputs.calls) != 0 {
				t.Fatalf("persistent lighting did not use one source change: %v %v", value, illumination.changes)
			}
			value = send(`{"method":"get","image":{"name":["switch","common"]},"video":{"name":"common"}}`)
			image := value["image"].(map[string]any)
			fields := image["switch"].(map[string]any)
			common := image["common"].(map[string]any)
			if fields["pre_night_vision_mode"] != "white_led_always_on" || fields["flicker"] != "60hz" || fields["switch_mode"] != "common" || common["smartwtl_digital_level"] != "42" || common["smartwtl"] != "manual" {
				t.Fatalf("readback does not combine source and virtual fields: %v", value)
			}
			illumination.settings.Mode, illumination.settings.Brightness = "auto_ir", 83
			value = send(`{"method":"get","image":{"name":["switch","common"]}}`)
			image = value["image"].(map[string]any)
			if image["switch"].(map[string]any)["pre_night_vision_mode"] != "auto_ir" || image["common"].(map[string]any)["smartwtl_digital_level"] != "83" {
				t.Fatalf("frontend retained stale lighting selection: %v", value)
			}
			illumination.settings.Mode = ""
			value = send(`{"method":"get","image":{"name":"switch"}}`)
			fields = value["image"].(map[string]any)["switch"].(map[string]any)
			if value["error_code"] != float64(0) || fields["pre_night_vision_mode"] != nil || fields["night_vision_mode"] != nil || fields["flicker"] != "60hz" {
				t.Fatalf("unmapped source policy was fabricated or lost other fields: %v", value)
			}
		})
	}
}

func TestNativeIlluminationRejectsWholeInvalidBatchBeforeSourceIO(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			illumination := &fakeIllumination{capability: IlluminationCapability{Modes: []string{"white_led_always_on"}, Brightness: true}, settings: IlluminationSettings{Mode: "white_led_always_on", Brightness: 50}}
			s := testServer(t, func(cfg *Config) { cfg.Illumination = illumination })
			send := outputTransport(t, s, transport)
			for _, body := range []string{
				`{"method":"set","image":{"switch":{"pre_night_vision_mode":"off"}}}`,
				`{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on","switch_mode":"schedule_switch"}}}`,
				`{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on","flicker":"60hz"}},"video":{"common":{"sensor_framerate":"bad"}}}`,
				`{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on"}},"system":{"basic":{"timezone":"UTC"}}}`,
				`{"method":"set","image":{"common":{"smartwtl_digital_level":42}}}`,
				`{"method":"set","image":{"common":{"smartwtl_digital_level":"101"}}}`,
				`{"method":"set","image":{"common":{"smartwtl_digital_level":"-1"}}}`,
				`{"method":"set","image":{"common":{"smartwtl_digital_level":null}}}`,
				`{"method":"set","image":{"common":{"smartwtl":"auto_wtl"}}}`,
				`{"method":"set","image":{"autoday":{"smartwtl_digital_level":"42"}}}`,
				`{"method":"set","image":{"switch":null}}`,
			} {
				if value := send(body); value["error_code"] != float64(unsupportedCode) || len(illumination.changes) != 0 || illumination.readCalls != 0 {
					t.Fatalf("invalid batch reached source: %s: %v", body, value)
				}
			}
			fields, _ := s.virtualImaging.read("image", "switch")
			if fields.(map[string]any)["flicker"] != "50hz" {
				t.Fatal("invalid batch changed virtual settings")
			}
			illumination.fail = true
			value := send(`{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on","flicker":"60hz"}}}`)
			fields, _ = s.virtualImaging.read("image", "switch")
			if value["error_code"] != float64(unsupportedCode) || fields.(map[string]any)["flicker"] != "50hz" {
				t.Fatalf("failed source write changed virtual settings: %v %v", value, fields)
			}
			value = send(`{"method":"get","image":{"name":"switch"}}`)
			if value["error_code"] != float64(unsupportedCode) {
				t.Fatalf("source read failure reported a lighting state: %v", value)
			}
		})
	}
}

func TestNativeIlluminationNilKeepsVirtualImagingAndNoPersistentOffer(t *testing.T) {
	s := testServer(t, nil)
	value := passthroughValue(t, s, `{"method":"get","image_capability":{"name":"supplement_lamp"}}`)
	if value["error_code"] != float64(unsupportedCode) {
		t.Fatalf("nil illumination advertised controls: %v", value)
	}
	value = passthroughValue(t, s, `{"method":"set","image":{"switch":{"flicker":"60hz"}},"video":{"common":{"sensor_framerate":"30"}}}`)
	if value["error_code"] != float64(0) {
		t.Fatalf("existing virtual settings regressed: %v", value)
	}
	value = passthroughValue(t, s, `{"method":"set","image":{"switch":{"pre_night_vision_mode":"white_led_always_on"}}}`)
	if value["error_code"] != float64(unsupportedCode) {
		t.Fatalf("nil illumination accepted persistent control: %v", value)
	}
}

func TestNativeIlluminationEmptyModesDisablePhysicalWrites(t *testing.T) {
	illumination := &fakeIllumination{capability: IlluminationCapability{Modes: []string{"unknown"}, Brightness: true, AutomaticBrightness: true}}
	s := testServer(t, func(cfg *Config) { cfg.Illumination = illumination })
	value := passthroughValue(t, s, `{"method":"set","image":{"common":{"smartwtl_digital_level":"42"}}}`)
	if value["error_code"] != float64(unsupportedCode) || len(illumination.changes) != 0 {
		t.Fatalf("empty supported policy set admitted a physical write: %v", value)
	}
	value = passthroughValue(t, s, `{"method":"get","image_capability":{"name":"supplement_lamp"}}`)
	if value["error_code"] != float64(unsupportedCode) {
		t.Fatalf("empty supported policy set advertised illumination: %v", value)
	}
}
