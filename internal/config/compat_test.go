package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCompatibilityDefaultsOffAndValidated(t *testing.T) {
	cfg := valid()
	if !reflect.DeepEqual(cfg.Cameras[0].Compatibility, Compatibility{}) || cfg.Validate() != nil {
		t.Fatal("compatibility experiments must be off by default")
	}
	for name, mutate := range map[string]func(*Compatibility){
		"unknown profile":    func(c *Compatibility) { c.ModuleSpecProfile = "donor" },
		"control characters": func(c *Compatibility) { c.ManufacturerName = "TP\x00LINK" },
		"long manufacturer":  func(c *Compatibility) { c.ManufacturerName = string(make([]byte, 65)) },
		"non-contiguous mask": func(c *Compatibility) {
			c.Network = &CompatibilityNetwork{Netmask: "255.0.255.0", Gateway: "192.0.2.1", DNS: "192.0.2.1"}
		},
		"broadcast gateway": func(c *Compatibility) {
			c.Network = &CompatibilityNetwork{Netmask: "255.255.255.0", Gateway: "255.255.255.255", DNS: "192.0.2.1"}
		},
		"missing dns": func(c *Compatibility) {
			c.Network = &CompatibilityNetwork{Netmask: "255.255.255.0", Gateway: "192.0.2.1"}
		},
		"host mask": func(c *Compatibility) {
			c.Network = &CompatibilityNetwork{Netmask: "255.255.255.255", Gateway: "192.0.2.1", DNS: "192.0.2.1"}
		},
		"ipv6 gateway in field": func(c *Compatibility) {
			c.Network = &CompatibilityNetwork{Netmask: "255.255.255.0", Gateway: "2001:db8::1", DNS: "192.0.2.1"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			mutate(&cfg.Cameras[0].Compatibility)
			if cfg.Validate() == nil {
				t.Fatal("invalid compatibility option accepted")
			}
		})
	}
	cfg = valid()
	cfg.Cameras[0].Compatibility = Compatibility{ModuleSpecProfile: "omada-ipc-observed", AdvertiseVHTTPD: true, ExtendedVideoFields: true, ExtendedIdentity: true,
		ManufacturerName: "Fixture Vendor", EncodeHTTPStrings: true, Network: &CompatibilityNetwork{Netmask: "255.255.255.0", Gateway: "192.0.2.1", DNS: "192.0.2.1"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Cameras[0].Compatibility.ModuleSpecProfile = "minimal"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibilityRoundTripsThroughStrictJSON(t *testing.T) {
	cfg := valid()
	cfg.Cameras[0].Compatibility = Compatibility{AdvertiseVHTTPD: true, Network: &CompatibilityNetwork{Netmask: "255.255.255.0", Gateway: "192.0.2.1", DNS: "192.0.2.1"}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	camera := fields["cameras"].([]any)[0].(map[string]any)
	compat, ok := camera["compatibility"].(map[string]any)
	if !ok || compat["advertise_vhttpd"] != true || compat["module_spec_profile"] != nil || compat["network"].(map[string]any)["gateway"] != "192.0.2.1" {
		t.Fatal("compatibility options did not serialize with omitted defaults")
	}
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil || loaded.Cameras[0].Compatibility.Network == nil || !loaded.Cameras[0].Compatibility.AdvertiseVHTTPD {
		t.Fatal("compatibility options did not load")
	}
	plain, _ := json.Marshal(valid())
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	if compat, present := fields["cameras"].([]any)[0].(map[string]any)["compatibility"]; present && len(compat.(map[string]any)) != 0 {
		t.Fatal("default compatibility serialized non-empty options")
	}
}
