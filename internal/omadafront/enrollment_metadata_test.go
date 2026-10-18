package omadafront

import (
	"encoding/json"
	"testing"
)

func TestEnrollmentReportsVirtualInterfaceAndProtocolVersion(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	_, response := request(t, s, path, `{"method":"get","function":{"name":"module_spec"},"network":{"name":"wan_status"}}`)
	wan := metadataObject(t, metadataObject(t, response["network"])["wan_status"])
	if wan["link_status"] != float64(1) || wan["phy_status"] != float64(1) || wan["ipaddr"] != "192.0.2.50" {
		t.Fatal("virtual network status does not match the reachable management endpoint")
	}
	for _, unobserved := range []string{"gateway", "netmask", "pri_dns", "snd_dns", "speed"} {
		if _, present := wan[unobserved]; present {
			t.Fatal("source network settings were fabricated")
		}
	}
	capabilities := metadataObject(t, metadataObject(t, response["function"])["module_spec"])
	if capabilities["omada_ipc"] != "1.0" || capabilities["smart_detection"] != "0" || capabilities["local_storage"] != "0" {
		t.Fatal("protocol version is missing or unsupported features are advertised")
	}
}

func TestEnrollmentVersionedSelectorsOnBothTransports(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	for _, raw := range []string{
		`{"method":"get","network":{"version":"1","name":"wan_status"}}`,
		`{"method":"get","upnpc":{"version":"1","name":"upnpc_info","table":["upnp_status"]}}`,
	} {
		_, response := request(t, s, path, raw)
		var callback map[string]any
		if err := json.Unmarshal(s.Passthrough(json.RawMessage(raw)), &callback); err != nil {
			t.Fatal(err)
		}
		if response["error_code"] != float64(0) || callback["error_code"] != float64(0) {
			t.Fatal("captured versioned selector was rejected")
		}
	}
	for _, raw := range []string{
		`{"method":"get","network":{"version":1,"name":"wan_status"}}`,
		`{"method":"get","network":{"version":"2","name":"wan_status"}}`,
		`{"method":"get","network":{"version":"1"}}`,
		`{"method":"get","network":{"version":"1","name":"wan_status","unknown":"value"}}`,
	} {
		_, response := request(t, s, path, raw)
		if response["error_code"] != float64(unsupportedCode) {
			t.Fatal("unknown or malformed selector version was accepted")
		}
	}
}
