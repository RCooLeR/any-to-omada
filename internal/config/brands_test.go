package config

import (
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
)

func TestBrandsSelectTheirEventAdapter(t *testing.T) {
	for brand, protocol := range map[string]string{
		"imou": ProtocolDVRIP, "dahua": ProtocolDVRIP, "amcrest": ProtocolDVRIP,
		"hikvision": ProtocolISAPI, "annke": ProtocolISAPI,
		"reolink": ProtocolONVIF, "axis": ProtocolONVIF, "hanwha": ProtocolONVIF, "uniview": ProtocolONVIF,
		"tapo": ProtocolONVIF, "bosch": ProtocolONVIF, "vivotek": ProtocolONVIF, "foscam": ProtocolONVIF, "onvif": ProtocolONVIF,
		"ring": "", "Hikvision": "",
	} {
		cfg := valid()
		cfg.Sources[0].Brand = brand
		if got := cfg.Sources[0].EventProtocol(); got != protocol {
			t.Fatalf("%s uses %q, want %q", brand, got, protocol)
		}
		if (cfg.Validate() == nil) != (protocol != "") {
			t.Fatalf("%s validation disagrees with its adapter", brand)
		}
	}
}

func TestIntelligentMappingsStayDVRIPOnly(t *testing.T) {
	cfg := valid()
	cfg.Sources[0].Brand = "reolink"
	cfg.Sources[0].EventMappings = []cameraevents.Mapping{{DeviceID: "dual", SourceIndex: 0, Code: "Intelligent", Discriminator: "336700", Class: "human"}}
	if cfg.Validate() == nil {
		t.Fatal("DVRIP Intelligent mapping accepted for an ONVIF source")
	}
	cfg.Sources[0].Brand = "imou"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
