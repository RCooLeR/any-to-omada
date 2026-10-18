package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPTZBlockIsOptionalAndValidated(t *testing.T) {
	cfg := valid()
	if cfg.Cameras[0].PTZ != nil || cfg.Validate() != nil {
		t.Fatal("PTZ must stay off by default")
	}
	cfg.Cameras[0].PTZ = &PTZ{ONVIFPort: 80, ProfileToken: "Profile000"}
	cfg.Cameras[0].Compatibility.PTZModuleSpecKeys = []string{"motor", "ptz"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Camera){
		"fixed lens":        func(c *Camera) { c.Lens = "fixed" },
		"missing port":      func(c *Camera) { c.PTZ.ONVIFPort = 0 },
		"unsafe token":      func(c *Camera) { c.PTZ.ProfileToken = "Profile000</t:ProfileToken>" },
		"long move":         func(c *Camera) { c.PTZ.MaxMoveSeconds = 61 },
		"unknown key":       func(c *Camera) { c.Compatibility.PTZModuleSpecKeys = []string{"target_track"} },
		"duplicate key":     func(c *Camera) { c.Compatibility.PTZModuleSpecKeys = []string{"motor", "motor"} },
		"keys without ptz":  func(c *Camera) { c.PTZ = nil },
		"negative move cap": func(c *Camera) { c.PTZ.MaxMoveSeconds = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			cfg.Cameras[0].PTZ = &PTZ{ONVIFPort: 80, ProfileToken: "Profile000"}
			cfg.Cameras[0].Compatibility.PTZModuleSpecKeys = []string{"motor"}
			mutate(&cfg.Cameras[0])
			if cfg.Validate() == nil {
				t.Fatal("invalid PTZ configuration accepted")
			}
		})
	}
}

func TestPTZBlockDecodesStrictly(t *testing.T) {
	var camera Camera
	decoder := json.NewDecoder(strings.NewReader(`{"ptz":{"onvif_port":80,"profile_token":"Profile000","max_move_seconds":5},"compatibility":{"ptz_module_spec_keys":["motor"]}}`))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&camera); err != nil || camera.PTZ.MaxMoveSeconds != 5 || camera.Compatibility.PTZModuleSpecKeys[0] != "motor" {
		t.Fatalf("decode: %v %+v", err, camera.PTZ)
	}
}
