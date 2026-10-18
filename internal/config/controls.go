package config

import "errors"

// WhiteLight enables native Lighting_V2 controls for one source lens. Profile
// selects its day/night configuration, not a different channel. RecorderModes
// opts into verified persistent illumination and temporary manual pulses;
// otherwise only the legacy experimental loopback pulse is enabled.
type WhiteLight struct {
	Profile    int `json:"profile"`
	Brightness int `json:"brightness"`
	// RecorderModes opts into persistent, source-backed recorder illumination.
	// An empty list retains the independent loopback test API only.
	RecorderModes []string `json:"recorder_modes,omitempty"`
}

// Deterrence enables the source's native manual alarm outputs. These are
// separate from steady illumination and from an external alarm-output relay.
// Every action is bounded by MaxAlarmSeconds even when the recorder omits Stop.
type Deterrence struct {
	SoundAlarm      bool `json:"sound_alarm"`
	LightAlarm      bool `json:"light_alarm"`
	MaxAlarmSeconds int  `json:"max_alarm_seconds"`
}

// AlarmOutput enables an explicitly selected ONVIF relay. Only existing
// monostable outputs with a device-side delay up to five seconds can be used.
type AlarmOutput struct {
	ONVIFPort  int    `json:"onvif_port"`
	RelayToken string `json:"relay_token"`
}

// validateControls requires a verified lens and bounds experimental light settings and
// explicitly selected ONVIF relay identifiers.
func (v Camera) validateControls(source Source) error {
	if v.WhiteLight != nil && ((source.Brand != "dahua" && source.Brand != "imou") || v.WhiteLight.Profile < 0 || v.WhiteLight.Profile > 7 || v.WhiteLight.Brightness < 1 || v.WhiteLight.Brightness > 100) {
		return errors.New("white_light requires a Dahua/Imou source, profile 0..7 and brightness 1..100")
	}
	if light := v.WhiteLight; light != nil {
		seen := map[string]bool{}
		for _, mode := range light.RecorderModes {
			if seen[mode] || (mode != "white_led_always_on" && mode != "auto_color" && mode != "auto_ir" && mode != "ir_always_on") {
				return errors.New("white_light recorder_modes must be unique supported illumination policies")
			}
			seen[mode] = true
		}
	}
	if v.AlarmOutput != nil && (v.AlarmOutput.ONVIFPort < 1 || v.AlarmOutput.ONVIFPort > 65535 || !profileToken.MatchString(v.AlarmOutput.RelayToken)) {
		return errors.New("alarm_output requires an ONVIF port and a valid relay token")
	}
	if d := v.Deterrence; d != nil {
		if (source.Brand != "dahua" && source.Brand != "imou") || (!d.SoundAlarm && !d.LightAlarm) || d.MaxAlarmSeconds < 1 || d.MaxAlarmSeconds > 5 {
			return errors.New("deterrence requires a Dahua/Imou source, at least one alarm output and max_alarm_seconds 1..5")
		}
	}
	if (v.WhiteLight != nil || v.AlarmOutput != nil || v.Deterrence != nil) && (!v.Verified || v.Lens == "unverified") {
		return errors.New("physical output controls require a verified source lens")
	}
	return nil
}
