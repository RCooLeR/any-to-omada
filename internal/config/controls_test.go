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
