package config

import "errors"

// WhiteLight enables experimental native Lighting_V2 pulse tests for one source
// lens. Profile selects its day/night configuration, not a different channel.
type WhiteLight struct {
	Profile    int `json:"profile"`
	Brightness int `json:"brightness"`
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
	if v.AlarmOutput != nil && (v.AlarmOutput.ONVIFPort < 1 || v.AlarmOutput.ONVIFPort > 65535 || !profileToken.MatchString(v.AlarmOutput.RelayToken)) {
		return errors.New("alarm_output requires an ONVIF port and a valid relay token")
	}
	if (v.WhiteLight != nil || v.AlarmOutput != nil) && (!v.Verified || v.Lens == "unverified") {
		return errors.New("physical output controls require a verified source lens")
	}
	return nil
}
