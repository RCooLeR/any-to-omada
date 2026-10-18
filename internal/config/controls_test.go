package config

import "testing"

func TestPhysicalOutputControlsRequireExplicitValidatedConfig(t *testing.T) {
	cfg := valid()
	if cfg.Cameras[0].WhiteLight != nil || cfg.Cameras[0].AlarmOutput != nil {
		t.Fatal("controls enabled by default")
	}
	cfg.Cameras[0].WhiteLight = &WhiteLight{Profile: 0, Brightness: 50}
	cfg.Cameras[0].AlarmOutput = &AlarmOutput{ONVIFPort: 80, RelayToken: "Relay1"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Cameras[0].WhiteLight.Brightness = 0 },
		func(c *Config) { c.Cameras[0].WhiteLight.Profile = 8 },
		func(c *Config) { c.Cameras[0].AlarmOutput.RelayToken = "<relay/>" },
		func(c *Config) { c.Cameras[0].AlarmOutput.ONVIFPort = 65536 },
		func(c *Config) { c.Cameras[0].Verified = false },
	} {
		c := valid()
		c.Cameras[0].WhiteLight = &WhiteLight{Profile: 0, Brightness: 50}
		c.Cameras[0].AlarmOutput = &AlarmOutput{ONVIFPort: 80, RelayToken: "Relay1"}
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid controls accepted")
		}
	}
}

func TestDeterrenceRequiresBoundedExplicitSupportedOutputs(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Cameras[0].Deterrence.SoundAlarm = false },
		func(c *Config) { c.Cameras[0].Deterrence.MaxAlarmSeconds = 0 },
		func(c *Config) { c.Cameras[0].Deterrence.MaxAlarmSeconds = 6 },
		func(c *Config) { c.Cameras[0].Verified = false },
		func(c *Config) { c.Sources[0].Brand = "onvif" },
	} {
		cfg := valid()
		cfg.Cameras[0].Deterrence = &Deterrence{SoundAlarm: true, MaxAlarmSeconds: 2}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		change(&cfg)
		if cfg.Validate() == nil {
			t.Fatal("invalid deterrence control accepted")
		}
	}
}

func TestNativePTZBackendDoesNotReuseONVIFFields(t *testing.T) {
	cfg := valid()
	cfg.Cameras[0].Lens = "ptz"
	cfg.Cameras[0].PTZ = &PTZ{Backend: "dvrip", MaxMoveSeconds: 2}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Cameras[0].PTZ.ProfileToken = "Profile000"
	if cfg.Validate() == nil {
		t.Fatal("native PTZ accepted ambiguous ONVIF profile")
	}
	cfg.Cameras[0].PTZ.ProfileToken = ""
	cfg.Sources[0].Brand = "onvif"
	if cfg.Validate() == nil {
		t.Fatal("native PTZ accepted unsupported source protocol")
	}
}

func TestRecorderIlluminationModesAreExplicitAndBounded(t *testing.T) {
	for _, modes := range [][]string{{"unknown"}, {"auto_ir", "auto_ir"}, {"off"}} {
		cfg := valid()
		cfg.Cameras[0].WhiteLight = &WhiteLight{Profile: 0, Brightness: 50, RecorderModes: modes}
		if cfg.Validate() == nil {
			t.Fatal("unsupported illumination policy accepted")
		}
	}
}
