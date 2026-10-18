package omadafront

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// OutputControls operates explicitly configured physical deterrence outputs.
// Start methods acknowledge source acceptance; implementations own bounded
// activation, cancellation, restoration, and shutdown independently of requests.
type OutputControls interface {
	// Capabilities returns configured, verified output modes without network I/O.
	Capabilities() OutputCapability
	// WhiteLight changes the steady lamp override, distinct from alarm flashing.
	WhiteLight(context.Context, bool) error
	// WhiteLightState reads the actual steady lamp override state.
	WhiteLightState(context.Context) (bool, error)
	// StartAlarm starts the selected outputs and returns their bounded duration in seconds.
	StartAlarm(context.Context, bool, bool) (int, error)
	// StopAlarm attempts termination even if support or selected settings have changed.
	StopAlarm(context.Context) error
}

// OutputCapability separates steady illumination from sound and flashing alarms.
// AlarmDuration is the fixed backend bound, not an adjustable NVR alarm setting.
type OutputCapability struct {
	WhiteLight, SoundAlarm, LightAlarm bool
	AlarmDuration                      time.Duration
}

// outputState stores manual alarm selections only; automatic event arming and
// schedules are unsupported. No network I/O occurs while mu is held.
type outputState struct {
	mu           sync.Mutex
	sound, light bool
}

const outputCallTimeout = 4 * time.Second

// outputCapability returns no physical features when no delegate is configured.
func (s *Server) outputCapability() OutputCapability {
	if s.outputs == nil {
		return OutputCapability{}
	}
	return s.outputs.Capabilities()
}

// outputModuleSpec limits opted-in output offers to implemented manual modes.
// Unconfigured cameras retain the observed enrollment compatibility profile.
func (s *Server) outputModuleSpec(spec map[string]any) {
	capability := s.outputCapability()
	if !capability.WhiteLight && !capability.SoundAlarm && !capability.LightAlarm {
		return
	}
	for _, key := range []string{"msg_alarm_list", "msg_alarm_separate_list", "msg_alarm_ver", "sound_alarm_version", "light_alarm_version", "usr_def_audio_alarm"} {
		delete(spec, key)
	}
	modes := []string{}
	if capability.SoundAlarm {
		modes = append(modes, "sound")
	}
	if capability.LightAlarm {
		modes = append(modes, "light")
	}
	if len(modes) > 0 {
		spec["msg_alarm_ver"] = "1.0"
		spec["msg_alarm_separate_list"] = modes
	}
}

// outputRead exposes manual selections and a source-confirmed steady-lamp state.
// It does not emulate automatic alarm schedules or adjustable siren settings.
func (s *Server) outputRead(module, name string) (any, bool) {
	capability := s.outputCapability()
	if module == "image_capability" && name == "supplement_lamp" && capability.WhiteLight {
		return map[string]any{"supplement_lamp_type": []string{"white_lamp"}, "white_light_manual_version": "1.0"}, true
	}
	if module == "light_control" && name == "white_light_manual" && capability.WhiteLight {
		ctx, cancel := context.WithTimeout(context.Background(), outputCallTimeout)
		defer cancel()
		on, err := s.outputs.WhiteLightState(ctx)
		if err != nil {
			return nil, false
		}
		return map[string]any{"switch": outputSwitch(on)}, true
	}
	if module != "msg_alarm" || (!capability.SoundAlarm && !capability.LightAlarm) {
		return nil, false
	}
	s.outputState.mu.Lock()
	sound, light := s.outputState.sound, s.outputState.light
	s.outputState.mu.Unlock()
	switch name {
	case "chn1_msg_alarm_info":
		modes := []string{}
		if capability.SoundAlarm {
			modes = append(modes, "sound")
		}
		if capability.LightAlarm {
			modes = append(modes, "light")
		}
		return map[string]any{"enabled": "off", "sound_alarm_enabled": outputSwitch(sound && capability.SoundAlarm),
			"light_alarm_enabled": outputSwitch(light && capability.LightAlarm), "alarm_mode": modes,
			"alarm_type": "0", "light_type": "1"}, true
	case "arming_status":
		return map[string]any{"sound": "disabled", "light": "disabled", "status": "disabled"}, true
	default:
		return nil, false
	}
}

// outputRequest validates one manual operation before any source I/O. Stop is
// independent of selection and capability discovery so an active output can end.
func (s *Server) outputRequest(ctx context.Context, method string, request map[string]json.RawMessage) (map[string]any, bool) {
	if s.outputs == nil || len(request) != 2 {
		return nil, false
	}
	if method == "set" {
		return s.outputSelection(request)
	}
	if method != "do" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, outputCallTimeout)
	defer cancel()
	if raw, exists := request["msg_alarm"]; exists {
		value, valid := outputAction(raw, "manual_msg_alarm", "action")
		if !valid || (value != "start" && value != "stop") {
			return nil, false
		}
		if value == "stop" {
			return outputResult(s.outputs.StopAlarm(ctx)), true
		}
		capability := s.outputCapability()
		s.outputState.mu.Lock()
		sound, light := s.outputState.sound, s.outputState.light
		s.outputState.mu.Unlock()
		if (!sound && !light) || (sound && !capability.SoundAlarm) || (light && !capability.LightAlarm) {
			return map[string]any{"error_code": unsupportedCode}, true
		}
		seconds, err := s.outputs.StartAlarm(ctx, sound, light)
		if err != nil || seconds < 1 || seconds > 35 {
			return map[string]any{"error_code": unsupportedCode}, true
		}
		return map[string]any{"timer": seconds, "error_code": 0}, true
	}
	if raw, exists := request["light_control"]; exists {
		value, valid := outputAction(raw, "white_light_manual", "switch")
		if !valid || (value != "on" && value != "off") {
			return nil, false
		}
		if value == "on" && !s.outputCapability().WhiteLight {
			return map[string]any{"error_code": unsupportedCode}, true
		}
		return outputResult(s.outputs.WhiteLight(ctx, value == "on")), true
	}
	return nil, false
}

// outputSelection atomically changes supported manual selection flags; any
// automatic-arming, schedule, custom-sound or unrelated field rejects the write.
func (s *Server) outputSelection(request map[string]json.RawMessage) (map[string]any, bool) {
	var sections map[string]json.RawMessage
	if json.Unmarshal(request["msg_alarm"], &sections) != nil || len(sections) != 1 {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(sections["chn1_msg_alarm_info"], &fields) != nil || len(fields) == 0 {
		return nil, false
	}
	capability := s.outputCapability()
	changes := map[string]bool{}
	for field, raw := range fields {
		var value string
		if json.Unmarshal(raw, &value) != nil || (value != "on" && value != "off") {
			return nil, false
		}
		switch field {
		case "enabled":
			if value != "off" {
				return nil, false
			}
		case "sound_alarm_enabled":
			if value == "on" && !capability.SoundAlarm {
				return nil, false
			}
			changes[field] = value == "on"
		case "light_alarm_enabled":
			if value == "on" && !capability.LightAlarm {
				return nil, false
			}
			changes[field] = value == "on"
		default:
			return nil, false
		}
	}
	s.outputState.mu.Lock()
	defer s.outputState.mu.Unlock()
	if value, exists := changes["sound_alarm_enabled"]; exists {
		s.outputState.sound = value
	}
	if value, exists := changes["light_alarm_enabled"]; exists {
		s.outputState.light = value
	}
	return map[string]any{"error_code": 0}, true
}

// outputAction accepts exactly one operation with one non-null string field.
func outputAction(raw json.RawMessage, operation, field string) (string, bool) {
	var operations map[string]json.RawMessage
	if json.Unmarshal(raw, &operations) != nil || len(operations) != 1 {
		return "", false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(operations[operation], &fields) != nil || len(fields) != 1 {
		return "", false
	}
	var value string
	if json.Unmarshal(fields[field], &value) != nil || value == "" {
		return "", false
	}
	return value, true
}

// outputResult exposes only the native status code, never source error details.
func outputResult(err error) map[string]any {
	if err != nil {
		return map[string]any{"error_code": unsupportedCode}
	}
	return map[string]any{"error_code": 0}
}

// outputSwitch uses the native camera's on/off string vocabulary.
func outputSwitch(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
