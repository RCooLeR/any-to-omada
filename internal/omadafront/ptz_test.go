package omadafront

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakePTZ records control requests without moving hardware and provides
// configurable source capabilities and preset data.
type fakePTZ struct {
	mu         sync.Mutex
	calls      []string
	presets    []PTZPreset
	fail       bool
	capability *PTZCapability
}

// record appends one control trace under the call-list mutex.
func (f *fakePTZ) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

// taken drains the recorded call list so each assertion owns its snapshot.
func (f *fakePTZ) taken() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

// Capability returns fixture PTZ support or the configured discovery failure.
func (f *fakePTZ) Capability(context.Context) (PTZCapability, error) {
	if f.fail {
		return PTZCapability{}, errors.New("unavailable")
	}
	if f.capability != nil {
		return *f.capability, nil
	}
	return PTZCapability{PanTilt: true, Zoom: true, MaxPresets: 8}, nil
}

// Move records normalized velocities instead of sending physical movement.
func (f *fakePTZ) Move(pan, tilt, zoom float64) {
	f.record(fmt.Sprintf("move %.2f %.2f %.2f", pan, tilt, zoom))
}

// Stop records an explicit stop command for order assertions.
func (f *fakePTZ) Stop() { f.record("stop") }

// Presets records discovery and returns the fixture positions.
func (f *fakePTZ) Presets(context.Context) ([]PTZPreset, error) {
	f.record("presets")
	return f.presets, nil
}

// GotoPreset records the requested recorder-facing position ID.
func (f *fakePTZ) GotoPreset(_ context.Context, id int) error {
	f.record(fmt.Sprintf("goto %d", id))
	return nil
}

// SetPreset records the save request and returns a fixed camera-selected ID.
func (f *fakePTZ) SetPreset(_ context.Context, id int, name string) (int, error) {
	f.record(fmt.Sprintf("set %d %s", id, name))
	return 4, nil
}

// RemovePreset records deletion without modifying source hardware.
func (f *fakePTZ) RemovePreset(_ context.Context, id int) error {
	f.record(fmt.Sprintf("remove %d", id))
	return nil
}

func passthroughValue(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPTZCommandsReachTheSourceLens(t *testing.T) {
	ptz := &fakePTZ{presets: []PTZPreset{{ID: 1, Name: "Door"}, {ID: 2, Name: "Yard"}}}
	s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
	for _, tc := range []struct {
		body, call string
		code       float64
	}{
		{`{"method":"do","ptz":{"move":{"chn_id":3,"direction":1,"speed":7}}}`, "move 1.00 0.00 0.00", 0},
		{`{"method":"do","ptz":{"move":{"direction":"6","speed":"4"}}}`, "move -0.57 0.57 0.00", 0},
		{`{"method":"do","ptz":{"move":{"direction":3,"speed":1}}}`, "move 0.00 -0.15 0.00", 0},
		{`{"method":"do","ptz":{"move":{"direction":10,"speed":7}}}`, "move 0.00 0.00 1.00", 0},
		{`{"method":"do","ptz":{"move":{"direction":0,"speed":4}}}`, "stop", 0},
		{`{"method":"do","ptz":{"move":{"direction":9,"speed":4}}}`, "", unsupportedCode},
		{`{"method":"do","ptz":{"continuous_move":{"velocity_pan":"-0.5","velocity_tilt":0.25,"velocity_zoom":"0"}}}`, "move -0.50 0.25 0.00", 0},
		{`{"method":"do","ptz":{"stop":null}}`, "stop", 0},
		{`{"method":"do","ptz":{"opt_preset":{"chn_id":3,"preset_id":2,"opt_type":2}}}`, "goto 2", 0},
		{`{"method":"do","ptz":{"opt_preset":{"chn_id":3,"preset_id":5,"opt_type":1}}}`, "remove 5", 0},
		{`{"method":"do","preset":{"goto_preset":{"id":"1"}}}`, "goto 1", 0},
		{`{"method":"do","preset":{"remove_preset":{"id":["1","2"]}}}`, "remove 1", 0},
	} {
		value := passthroughValue(t, s, tc.body)
		calls := ptz.taken()
		if value["error_code"] != tc.code || (tc.call == "" && len(calls) != 0) || (tc.call != "" && (len(calls) == 0 || calls[0] != tc.call)) {
			t.Fatalf("%s: code %v calls %v", tc.body, value["error_code"], calls)
		}
	}
	value := passthroughValue(t, s, `{"method":"do","ptz":{"opt_preset":{"chn_id":3,"opt_type":0,"preset_name":"Gate","save_ptz":0}}}`)
	if value["error_code"] != float64(0) || value["preset_id"] != float64(4) || !reflect.DeepEqual(ptz.taken(), []string{"set 0 Gate"}) {
		t.Fatalf("save preset: %v", value)
	}
	value = passthroughValue(t, s, `{"method":"do","ptz":{"get_preset":{"chn_id":3}}}`)
	rows, _ := value["preset"].([]any)
	if value["error_code"] != float64(0) || len(rows) != 2 || !reflect.DeepEqual(rows[1], map[string]any{"preset_id": float64(2), "name": "Yard"}) {
		t.Fatalf("presets: %v", value)
	}
}

func TestPTZCapabilityAndModuleSpecCandidates(t *testing.T) {
	ptz := &fakePTZ{}
	s := testServer(t, func(cfg *Config) {
		cfg.PTZ = ptz
		cfg.Compatibility.PTZModuleSpecKeys = []string{"motor", "ptz"}
	})
	value := passthroughValue(t, s, `{"method":"get","function":{"name":"module_spec"},"ptz":{"name":"capability"}}`)
	spec := value["function"].(map[string]any)["module_spec"].(map[string]any)
	if spec["motor"] != "1" || spec["ptz"] != "1" {
		t.Fatalf("module_spec lacks candidate keys: %v", spec)
	}
	capability := value["ptz"].(map[string]any)["capability"].(map[string]any)
	if capability["continuous_move_supported"] != "1" || capability["zoom_supported"] != "0" || capability["preset_supported"] != "0" || capability["preset_number_max"] != "0" ||
		capability["focus_supported"] != "0" || capability["tour_supported"] != "0" {
		t.Fatalf("native capability: %v", capability)
	}
	value = passthroughValue(t, s, `{"method":"do","ptz":{"get_ptz_capability":{"chn_id":3}}}`)
	capability = value["ptz_capability"].(map[string]any)
	if capability["zoom_supported"] != "1" || capability["preset_supported"] != "1" || capability["preset_number_max"] != "8" || capability["continuous_move_supported"] != nil {
		t.Fatalf("get_ptz_capability: %v", value)
	}

	ptz.fail = true
	if value := passthroughValue(t, s, `{"method":"do","ptz":{"get_ptz_capability":{}}}`); value["error_code"] != float64(unsupportedCode) {
		t.Fatal("unavailable source reported PTZ capability")
	}
}

func TestNativePTZCapabilityDoesNotClaimUnverifiedControls(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		for _, source := range []struct {
			name    string
			panTilt bool
			fail    bool
		}{
			{name: "pan_tilt", panTilt: true},
			{name: "zoom_only"},
			{name: "discovery_failure", panTilt: true, fail: true},
		} {
			t.Run(transport+"/"+source.name, func(t *testing.T) {
				ptz := &fakePTZ{capability: &PTZCapability{PanTilt: source.panTilt, Zoom: true, MaxPresets: 8, Home: true}, fail: source.fail}
				s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
				body := `{"method":"get","ptz":{"name":"capability"}}`
				var value map[string]any
				if transport == "callback" {
					value = passthroughValue(t, s, body)
				} else {
					var status int
					status, value = request(t, s, login(t, s), body)
					if status != http.StatusOK {
						t.Fatalf("authenticated request returned HTTP %d", status)
					}
				}
				if source.fail {
					if !reflect.DeepEqual(value, map[string]any{"error_code": float64(unsupportedCode)}) {
						t.Fatalf("unavailable source reported native PTZ capability: %v", value)
					}
					return
				}
				capability := value["ptz"].(map[string]any)["capability"].(map[string]any)
				continuousMove := "0"
				if source.panTilt {
					continuousMove = "1"
				}
				if value["error_code"] != float64(0) || capability["continuous_move_supported"] != continuousMove ||
					capability["zoom_supported"] != "0" || capability["preset_supported"] != "0" || capability["preset_number_max"] != "0" ||
					capability["absolute_move_supported"] != "0" || capability["relative_move_supported"] != "0" {
					t.Fatalf("native capability overclaimed source controls: %v", value)
				}
				for _, name := range []string{"position_pan_range", "position_tilt_range", "position_zoom_range", "home_position_mode", "status"} {
					if _, found := capability[name]; found {
						t.Fatalf("native capability invented %s: %v", name, capability)
					}
				}
				if len(ptz.taken()) != 0 {
					t.Fatal("capability read issued a physical control")
				}
			})
		}
	}
}

func TestNativeContinuousMoveAndStopBodiesReachSource(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			ptz := &fakePTZ{}
			s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
			path := login(t, s)
			for _, command := range []struct {
				body string
				call string
			}{
				{`{"method":"do","ptz":{"continuous_move":{"velocity_pan":"0.571429","velocity_tilt":"-0.571429"}}}`, "move 0.57 -0.57 0.00"},
				{`{"method":"do","ptz":{"stop":{"pan":"1","tilt":"1","zoom":"1"}}}`, "stop"},
			} {
				var value map[string]any
				if transport == "callback" {
					value = passthroughValue(t, s, command.body)
				} else {
					var status int
					status, value = request(t, s, path, command.body)
					if status != http.StatusOK {
						t.Fatalf("authenticated request returned HTTP %d", status)
					}
				}
				if calls := ptz.taken(); !reflect.DeepEqual(value, map[string]any{"error_code": float64(0)}) || !reflect.DeepEqual(calls, []string{command.call}) {
					t.Fatalf("native command response %v, calls %v", value, calls)
				}
			}
		})
	}
}

func TestNativePresetReadDoesNotReturnRecorderUIShape(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			ptz := &fakePTZ{presets: []PTZPreset{{ID: 1, Name: "Door"}}}
			s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
			path := login(t, s)
			read := func(body string) map[string]any {
				if transport == "callback" {
					return passthroughValue(t, s, body)
				}
				status, value := request(t, s, path, body)
				if status != http.StatusOK {
					t.Fatalf("authenticated request returned HTTP %d", status)
				}
				return value
			}
			for _, body := range []string{
				`{"method":"do","preset":{"get_preset":{"count":"300","position_info":"none","start_id":"0"}}}`,
				`{"method":"do","preset":{"get_preset":{"type":"index","count":"300","position_info":"none","start_index":"0"}}}`,
			} {
				value := read(body)
				if !reflect.DeepEqual(value, map[string]any{"error_code": float64(unsupportedCode)}) || len(ptz.taken()) != 0 {
					t.Fatalf("native preset read queried the source or returned a guessed success payload: %v", value)
				}
			}
			value := read(`{"method":"do","ptz":{"get_preset":{"chn_id":3}}}`)
			rows, _ := value["preset"].([]any)
			if value["error_code"] != float64(0) || len(rows) != 1 || !reflect.DeepEqual(rows[0], map[string]any{"preset_id": float64(1), "name": "Door"}) || !reflect.DeepEqual(ptz.taken(), []string{"presets"}) {
				t.Fatalf("recorder UI preset read changed: %v", value)
			}
		})
	}
}

func TestPTZStaysUnsupportedWithoutController(t *testing.T) {
	s := testServer(t, func(cfg *Config) { cfg.Compatibility.PTZModuleSpecKeys = []string{"motor"} })
	value := passthroughValue(t, s, `{"method":"get","function":{"name":"module_spec"}}`)
	if _, found := value["function"].(map[string]any)["module_spec"].(map[string]any)["motor"]; found {
		t.Fatal("PTZ keys advertised without a controller")
	}
	if value := passthroughValue(t, s, `{"method":"do","ptz":{"move":{"direction":1,"speed":4}}}`); value["error_code"] != float64(unsupportedCode) {
		t.Fatal("PTZ command accepted without a controller")
	}
	if value := passthroughValue(t, s, `{"method":"get","ptz":{"name":"capability"}}`); value["error_code"] != float64(unsupportedCode) {
		t.Fatal("PTZ capability answered without a controller")
	}
}

func TestPTZOverHTTPSRequiresSession(t *testing.T) {
	ptz := &fakePTZ{}
	s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
	body := `{"method":"do","ptz":{"move":{"direction":7,"speed":7}}}`
	if code, _ := request(t, s, "/stok=/ds", body); code != http.StatusUnauthorized || len(ptz.taken()) != 0 {
		t.Fatal("unauthenticated PTZ command executed")
	}
	if code, value := request(t, s, login(t, s), body); code != http.StatusOK || value["error_code"] != float64(0) || !reflect.DeepEqual(ptz.taken(), []string{"move 0.00 1.00 0.00"}) {
		t.Fatalf("authenticated PTZ command: %v", value)
	}
}

func TestMalformedPTZCommandsDoNotReachTheSource(t *testing.T) {
	cases := []struct{ name, operation string }{
		{"null_direction", `"ptz":{"move":{"direction":null}}`},
		{"fractional_direction", `"ptz":{"move":{"direction":1.5}}`},
		{"fractional_string_direction", `"ptz":{"move":{"direction":"1.5"}}`},
		{"negative_direction", `"ptz":{"move":{"direction":-1}}`},
		{"large_direction", `"ptz":{"move":{"direction":1e100}}`},
		{"null_speed", `"ptz":{"move":{"direction":1,"speed":null}}`},
		{"invalid_speed", `"ptz":{"move":{"direction":1,"speed":"fast"}}`},
		{"zero_speed", `"ptz":{"move":{"direction":1,"speed":0}}`},
		{"negative_speed", `"ptz":{"move":{"direction":1,"speed":-1}}`},
		{"large_speed", `"ptz":{"move":{"direction":1,"speed":8}}`},
		{"infinite_speed", `"ptz":{"move":{"direction":1,"speed":"+Inf"}}`},
		{"empty_velocity", `"ptz":{"continuous_move":{}}`},
		{"null_velocity_body", `"ptz":{"continuous_move":null}`},
		{"null_velocity", `"ptz":{"continuous_move":{"velocity_pan":null}}`},
		{"malformed_velocity", `"ptz":{"continuous_move":{"velocity_pan":0.5,"velocity_tilt":"up"}}`},
		{"nan_velocity", `"ptz":{"continuous_move":{"velocity_pan":"NaN"}}`},
		{"large_velocity", `"ptz":{"continuous_move":{"velocity_zoom":1.1}}`},
		{"negative_velocity", `"ptz":{"continuous_move":{"velocity_tilt":-1.1}}`},
		{"null_preset_operation", `"ptz":{"opt_preset":{"opt_type":null}}`},
		{"fractional_preset_operation", `"ptz":{"opt_preset":{"opt_type":2.5,"preset_id":1}}`},
		{"missing_goto_id", `"ptz":{"opt_preset":{"opt_type":2}}`},
		{"null_goto_id", `"preset":{"goto_preset":{"id":null}}`},
		{"zero_goto_id", `"preset":{"goto_preset":{"id":0}}`},
		{"fractional_goto_id", `"preset":{"goto_preset":{"id":1.5}}`},
		{"large_goto_id", `"preset":{"goto_preset":{"id":65536}}`},
		{"negative_goto_id", `"preset":{"goto_preset":{"id":-1}}`},
		{"missing_delete_id", `"ptz":{"opt_preset":{"opt_type":1}}`},
		{"null_delete_id", `"preset":{"remove_preset":{"id":null}}`},
		{"fractional_delete_id", `"preset":{"remove_preset":{"id":"2.5"}}`},
		{"null_create_body", `"preset":{"set_preset":null}`},
		{"scalar_create_body", `"preset":{"set_preset":3}`},
		{"array_create_body", `"preset":{"set_preset":[]}`},
		{"null_create_id", `"preset":{"set_preset":{"id":null}}`},
		{"fractional_create_id", `"preset":{"set_preset":{"id":"1.5"}}`},
		{"invalid_create_id", `"ptz":{"opt_preset":{"opt_type":0,"preset_id":"bad"}}`},
		{"null_create_name", `"preset":{"set_preset":{"name":null}}`},
		{"invalid_create_name", `"ptz":{"opt_preset":{"opt_type":0,"preset_name":42}}`},
		{"null_deletion_list", `"ptz":{"opt_preset":{"opt_type":5,"preset_id_list":null}}`},
		{"empty_deletion_list", `"preset":{"remove_preset":{"id":[]}}`},
		{"partly_invalid_deletion_list", `"preset":{"remove_preset":{"id":[1,"bad",2]}}`},
		{"partly_fractional_deletion_list", `"ptz":{"opt_preset":{"opt_type":5,"preset_id_list":[1,2.5]}}`},
		{"partly_null_deletion_list", `"preset":{"remove_preset":{"id":[1,null]}}`},
		{"partly_large_deletion_list", `"preset":{"remove_preset":{"id":[1,65536]}}`},
		{"partly_zero_deletion_list", `"preset":{"remove_preset":{"id":[1,0]}}`},
		{"oversized_deletion_list", `"preset":{"remove_preset":{"id":[` + strings.Repeat("1,", 256) + `1]}}`},
	}
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			ptz := &fakePTZ{}
			s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
			session := login(t, s)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					body := `{"method":"do",` + tc.operation + `}`
					var value map[string]any
					if transport == "https" {
						_, value = request(t, s, session, body)
					} else {
						value = passthroughValue(t, s, body)
					}
					if calls := ptz.taken(); value["error_code"] != float64(unsupportedCode) || len(calls) != 0 {
						t.Fatalf("malformed command returned %v and source calls %v", value, calls)
					}
				})
			}
		})
	}
}

func TestPTZOptionalFieldsAndValidatedPresetList(t *testing.T) {
	ptz := &fakePTZ{}
	s := testServer(t, func(cfg *Config) { cfg.PTZ = ptz })
	for _, tc := range []struct {
		body  string
		calls []string
	}{
		{`{"method":"do","ptz":{"move":{"direction":"1"}}}`, []string{"move 0.57 0.00 0.00"}},
		{`{"method":"do","ptz":{"continuous_move":{"velocity_pan":1}}}`, []string{"move 1.00 0.00 0.00"}},
		{`{"method":"do","preset":{"set_preset":{"name":"Gate"}}}`, []string{"set 0 Gate"}},
		{`{"method":"do","preset":{"set_preset":{"id":"0","name":"Gate"}}}`, []string{"set 0 Gate"}},
		{`{"method":"do","preset":{"set_preset":{"id":"65535","name":"Gate"}}}`, []string{"set 65535 Gate"}},
		{`{"method":"do","ptz":{"opt_preset":{"opt_type":"5","preset_id_list":[1,"2",65535]}}}`, []string{"remove 1", "remove 2", "remove 65535"}},
		{`{"method":"do","preset":{"remove_preset":{"id":"2"}}}`, []string{"remove 2"}},
	} {
		value := passthroughValue(t, s, tc.body)
		if calls := ptz.taken(); value["error_code"] != float64(0) || !reflect.DeepEqual(calls, tc.calls) {
			t.Fatalf("%s: response %v calls %v, want %v", tc.body, value, calls, tc.calls)
		}
	}
}

func TestUnknownOperationsAreLoggedByNameOnly(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) {
		cfg.PTZ = &fakePTZ{}
		cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil))
	})
	value := passthroughValue(t, s, `{"method":"do","ptz":{"opt_quick_tour":{"chn_id":3,"tour_name":"private-tour","password":"private-value","position":{"pan":"0.4","tilt":"x"}}}}`)
	if value["error_code"] != float64(unsupportedCode) {
		t.Fatal("unknown PTZ operation accepted")
	}
	var fields struct {
		Operation string   `json:"operation"`
		Shape     []string `json:"request_shape"`
	}
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"ptz.opt_quick_tour{chn_id,redacted,position{pan,tilt},tour_name}"}
	if !reflect.DeepEqual(fields.Shape, want) {
		t.Fatalf("shape = %v", fields.Shape)
	}
	if strings.Contains(output.String(), "private") || strings.Contains(output.String(), "0.4") || strings.Contains(output.String(), "password") {
		t.Fatalf("diagnostics exposed values: %s", output.String())
	}
}

func TestRequestShapeIsBounded(t *testing.T) {
	if got := RequestShape(json.RawMessage(`{"method":"get","ptz":{"name":["capability","bad name"]},"x-y":{"a":1}}`)); !reflect.DeepEqual(got, []string{"ptz.name=capability,?", "?.a:number"}) {
		t.Fatalf("shape = %v", got)
	}
	if got := RequestShape(json.RawMessage(`"text"`)); !reflect.DeepEqual(got, []string{"invalid"}) {
		t.Fatalf("shape = %v", got)
	}
	var many strings.Builder
	many.WriteString(`{"method":"do"`)
	for i := range 40 {
		fmt.Fprintf(&many, `,"m%02d":{"a":{},"b":{},"c":{}}`, i)
	}
	many.WriteString("}")
	if got := RequestShape(json.RawMessage(many.String())); len(got) > 16 || got[len(got)-1] != "truncated" {
		t.Fatalf("unbounded shape: %d", len(got))
	}
}
