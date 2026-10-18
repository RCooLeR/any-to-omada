package omadafront

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeOutputs records accepted output commands and configurable source failures.
type fakeOutputs struct {
	capability OutputCapability
	calls      []string
	fail       bool
	whiteLight bool
}

// Capabilities returns the explicit fixture modes without simulated discovery.
func (f *fakeOutputs) Capabilities() OutputCapability { return f.capability }

// WhiteLight records the steady lamp override and changes state only on success.
func (f *fakeOutputs) WhiteLight(_ context.Context, on bool) error {
	f.calls = append(f.calls, fmt.Sprintf("white %t", on))
	if f.fail {
		return errors.New("source-private-detail")
	}
	f.whiteLight = on
	return nil
}

// WhiteLightState returns fixture hardware state, not a frontend assumption.
func (f *fakeOutputs) WhiteLightState(context.Context) (bool, error) {
	f.calls = append(f.calls, "white state")
	if f.fail {
		return false, errors.New("source-private-detail")
	}
	return f.whiteLight, nil
}

// StartAlarm records the selected outputs and only then acknowledges the bound.
func (f *fakeOutputs) StartAlarm(_ context.Context, sound, light bool) (int, error) {
	f.calls = append(f.calls, fmt.Sprintf("start %t %t", sound, light))
	if f.fail {
		return 0, errors.New("source-private-detail")
	}
	return int(f.capability.AlarmDuration / time.Second), nil
}

// StopAlarm records a stop independently of discovery and configured selection.
func (f *fakeOutputs) StopAlarm(context.Context) error {
	f.calls = append(f.calls, "stop")
	if f.fail {
		return errors.New("source-private-detail")
	}
	return nil
}

// outputTransport exercises the same native operation through either authenticated path.
func outputTransport(t *testing.T, s *Server, transport string) func(string) map[string]any {
	t.Helper()
	if transport == "callback" {
		return func(body string) map[string]any { return passthroughValue(t, s, body) }
	}
	path := login(t, s)
	return func(body string) map[string]any {
		status, value := request(t, s, path, body)
		if status != http.StatusOK {
			t.Fatalf("authenticated output request returned HTTP %d", status)
		}
		return value
	}
}

func TestNativeAlarmControlsAcknowledgeSourceAndHonorManualSelection(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			outputs := &fakeOutputs{capability: OutputCapability{SoundAlarm: true, LightAlarm: true, AlarmDuration: 5 * time.Second}}
			s := testServer(t, func(cfg *Config) { cfg.Outputs = outputs })
			send := outputTransport(t, s, transport)
			value := send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}`)
			if value["error_code"] != float64(0) || value["timer"] != float64(5) || !reflect.DeepEqual(outputs.calls, []string{"start true true"}) {
				t.Fatalf("start did not acknowledge source-selected outputs: %v %v", value, outputs.calls)
			}
			value = send(`{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"sound_alarm_enabled":"off","enabled":"off"}}}`)
			if value["error_code"] != float64(0) {
				t.Fatalf("manual selection rejected: %v", value)
			}
			value = send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}`)
			if value["error_code"] != float64(0) || outputs.calls[len(outputs.calls)-1] != "start false true" {
				t.Fatalf("selected light-only alarm not forwarded: %v %v", value, outputs.calls)
			}
			outputs.fail = true
			value = send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}`)
			if value["error_code"] != float64(unsupportedCode) || value["timer"] != nil {
				t.Fatalf("source failure reported successful alarm: %v", value)
			}
			outputs.fail = false
			outputs.capability = OutputCapability{}
			value = send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"stop"}}}`)
			if value["error_code"] != float64(0) || outputs.calls[len(outputs.calls)-1] != "stop" {
				t.Fatalf("stop depended on current support: %v %v", value, outputs.calls)
			}
		})
	}
}

func TestNativeOutputValidationRejectsCompositeAndAutomaticWrites(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			outputs := &fakeOutputs{capability: OutputCapability{LightAlarm: true, AlarmDuration: 5 * time.Second}}
			s := testServer(t, func(cfg *Config) { cfg.Outputs = outputs })
			send := outputTransport(t, s, transport)
			for _, body := range []string{
				`{"method":"do","msg_alarm":{"manual_msg_alarm":null}}`,
				`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":null}}}`,
				`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start","timer":5}}}`,
				`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"},"arming_status":{"action":"arm"}}}`,
				`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}},"light_control":{"white_light_manual":{"switch":"on"}}}`,
				`{"method":"do","msg_alarm":{"arming_status":{"action":"arm"}}}`,
				`{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"enabled":"on"}}}`,
				`{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"off","sound_alarm_enabled":"on"}}}`,
				`{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"off","sound_alarm_custom":"on"}}}`,
				`{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"off"}},"msg_alarm_plan":{"arming_schedule_light":{"monday":"[]"}}}`,
				`{"method":"set","light_control":{"light_alarm_info":{"light_alarm_frequency":"high"}}}`,
				`{"method":"do","light_control":{"white_light_manual":{"switch":"on"}}}`,
			} {
				if value := send(body); value["error_code"] != float64(unsupportedCode) || len(outputs.calls) != 0 {
					t.Fatalf("invalid request reached source: %s: %v %v", body, value, outputs.calls)
				}
			}
			value := send(`{"method":"get","msg_alarm":{"name":"chn1_msg_alarm_info"}}`)
			fields := value["msg_alarm"].(map[string]any)["chn1_msg_alarm_info"].(map[string]any)
			if fields["light_alarm_enabled"] != "on" || fields["sound_alarm_enabled"] != "off" || fields["enabled"] != "off" {
				t.Fatalf("rejected composite write changed selections: %v", fields)
			}
		})
	}
}

func TestNativeOutputsRemoveUnsupportedDonorOffers(t *testing.T) {
	for _, outputs := range []*fakeOutputs{{capability: OutputCapability{WhiteLight: true}}, {capability: OutputCapability{LightAlarm: true, AlarmDuration: 5 * time.Second}}} {
		s := testServer(t, func(cfg *Config) {
			cfg.Compatibility.ObservedModuleSpec = true
			cfg.Outputs = outputs
		})
		value := passthroughValue(t, s, `{"method":"get","function":{"name":"module_spec"}}`)
		spec := value["function"].(map[string]any)["module_spec"].(map[string]any)
		for _, key := range []string{"usr_def_audio_alarm", "sound_alarm_version", "light_alarm_version", "msg_alarm_list"} {
			if spec[key] != nil {
				t.Fatalf("unimplemented capability %s still advertised", key)
			}
		}
		if outputs.capability.WhiteLight {
			if spec["msg_alarm_separate_list"] != nil || spec["msg_alarm_ver"] != nil {
				t.Fatal("steady-light controller advertises alarm controls")
			}
		} else if !reflect.DeepEqual(spec["msg_alarm_separate_list"], []any{"light"}) || spec["msg_alarm_ver"] != "1.0" {
			t.Fatalf("capability does not match supported light-only mode: %v", spec)
		}
	}
}

func TestNativeSteadyWhiteLightUsesDistinctBackendAndReadback(t *testing.T) {
	for _, transport := range []string{"https", "callback"} {
		t.Run(transport, func(t *testing.T) {
			outputs := &fakeOutputs{capability: OutputCapability{WhiteLight: true}}
			s := testServer(t, func(cfg *Config) { cfg.Outputs = outputs })
			send := outputTransport(t, s, transport)
			if value := send(`{"method":"do","light_control":{"white_light_manual":{"switch":"on"}}}`); value["error_code"] != float64(0) {
				t.Fatalf("steady lamp start failed: %v", value)
			}
			value := send(`{"method":"get","light_control":{"name":"white_light_manual"},"image_capability":{"name":"supplement_lamp"}}`)
			if value["light_control"].(map[string]any)["white_light_manual"].(map[string]any)["switch"] != "on" ||
				value["image_capability"].(map[string]any)["supplement_lamp"].(map[string]any)["white_light_manual_version"] != "1.0" {
				t.Fatalf("steady lamp state or capability missing: %v", value)
			}
			outputs.capability = OutputCapability{}
			if value := send(`{"method":"do","light_control":{"white_light_manual":{"switch":"off"}}}`); value["error_code"] != float64(0) {
				t.Fatalf("steady lamp stop depended on capability: %v", value)
			}
			if !reflect.DeepEqual(outputs.calls, []string{"white true", "white state", "white false"}) {
				t.Fatalf("steady lamp used an alarm action: %v", outputs.calls)
			}
		})
	}
}

func TestNativeOutputDiagnosticsDoNotExposeInputOrSourceError(t *testing.T) {
	var logs bytes.Buffer
	outputs := &fakeOutputs{capability: OutputCapability{LightAlarm: true, AlarmDuration: 5 * time.Second}, fail: true}
	s := testServer(t, func(cfg *Config) {
		cfg.Outputs = outputs
		cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	})
	for _, transport := range []string{"https", "callback"} {
		send := outputTransport(t, s, transport)
		send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"source-private-input"}}}`)
		send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}`)
	}
	if strings.Contains(logs.String(), "source-private") {
		t.Fatal("output diagnostics leaked arbitrary input or source error")
	}
}
