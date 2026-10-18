package omadafront

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func metadataObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("management section is not an object")
	}
	return object
}

func TestMetadataBatchedIdentityAndVideoUseSourceFactsAndVirtualIdentity(t *testing.T) {
	metadataCalls := 0
	s := testServer(t, func(cfg *Config) {
		cfg.MAC = [6]byte{0x02, 0xa4, 0xb6, 0xc8, 0xda, 0xec}
		cfg.Metadata = func() Metadata {
			metadataCalls++
			return Metadata{Name: "fixture-lens", Brand: "Imou", Model: "IPC-fixture", Firmware: "2.680.fixture.R", BuildDate: "2024-12-02", SoftwareVersion: "test-translator",
				Video: map[string]VideoMetadata{
					"main":  {Codec: "H265", Width: 1920, Height: 1080, BitrateKbps: 1024, BitrateMode: "cbr", FrameRateNumerator: 25000, FrameRateDenominator: 1000},
					"minor": {Codec: "H264", Width: 640, Height: 480, BitrateKbps: 512, BitrateMode: "cbr", FrameRateNumerator: 25, FrameRateDenominator: 1},
				}}
		}
	})
	path := login(t, s)
	code, response := request(t, s, path, `{"method":"get","device_info":{"name":["basic_info","info"]},"video":{"name":["main","minor","unknown"]},"network":{"name":"wan_status"}}`)
	if code != http.StatusOK || response["error_code"] != float64(0) || metadataCalls != 1 {
		t.Fatal("batched read failed or did not use one metadata snapshot")
	}
	identity := metadataObject(t, response["device_info"])
	for _, name := range []string{"basic_info", "info"} {
		info := metadataObject(t, identity[name])
		if info["device_model"] != "Imou IPC-fixture · AnyToOmada" || info["sw_version"] != "2.680.fixture.R 2024-12-02 · translator test-translator" ||
			info["device_name"] != "fixture-lens" || info["manufacturer_name"] != "AnyToOmada" {
			t.Fatal("identity omitted source facts or misrepresented the translator as a donor camera")
		}
		if info["serial_number"] != nil || info["hardware_version"] != nil {
			t.Fatal("unavailable donor identity was fabricated")
		}
	}
	basic := metadataObject(t, identity["basic_info"])
	wan := metadataObject(t, metadataObject(t, response["network"])["wan_status"])
	if basic["mac"] != "02-a4-b6-c8-da-ec" || wan["mac"] != basic["mac"] || wan["ipaddr"] != "192.0.2.50" {
		t.Fatal("device and network identities disagree with the virtual endpoint")
	}
	video := metadataObject(t, response["video"])
	if len(video) != 2 || video["unknown"] != nil {
		t.Fatal("unknown video profile was advertised")
	}
	want := map[string]any{
		"main":  map[string]any{"name": "VideoEncoder_1", "quality": "3", "encode_type": "H265", "resolution": "1920*1080", "bitrate": "1024", "bitrate_type": "cbr", "frame_rate": "65561"},
		"minor": map[string]any{"name": "VideoEncoder_2", "quality": "3", "encode_type": "H264", "resolution": "640*480", "bitrate": "512", "bitrate_type": "cbr", "frame_rate": "65561"},
	}
	if !reflect.DeepEqual(video, want) {
		t.Fatal("source video facts or native numeric-string types were changed")
	}
}

func TestMetadataFrameRateEncodingOmitsUnknownAndFractionalRates(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		numerator, denominator uint32
		want                   string
	}{
		{"integer", 25, 1, "65561"},
		{"reducible integer", 30000, 1000, "65566"},
		{"fractional", 30000, 1001, ""},
		{"fractional half", 25000, 2000, ""},
		{"missing denominator", 25, 0, ""},
		{"zero", 0, 1, ""},
		{"outside supported rate", 241, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := VideoMetadata{Codec: "H264", Width: 640, Height: 480, FrameRateNumerator: tc.numerator, FrameRateDenominator: tc.denominator}
			fields := profile.fields()
			if tc.want == "" {
				if _, present := fields["frame_rate"]; present {
					t.Fatal("unknown or fractional rate was invented")
				}
			} else if fields["frame_rate"] != tc.want {
				t.Fatal("integer rate does not match the native 65536 offset")
			}
			if _, present := fields["bitrate"]; present || fields["bitrate_type"] != nil {
				t.Fatal("unknown bitrate settings were advertised")
			}
		})
	}
}

func TestMetadataIncompleteProfilesAreOmittedWithoutInventingCapabilities(t *testing.T) {
	s := testServer(t, func(cfg *Config) {
		cfg.Metadata = func() Metadata {
			return Metadata{Video: map[string]VideoMetadata{
				"main": {Codec: "H265", Width: 1920}, "minor": {Codec: "MJPEG", Width: 640, Height: 480},
			}}
		}
	})
	path := login(t, s)
	_, response := request(t, s, path, `{"method":"get","video":{"name":["main","minor","unknown"]},"network":{"name":"wan_status"},"unknown":{"name":"anything"}}`)
	if response["error_code"] != float64(0) || response["network"] == nil || response["video"] != nil || response["unknown"] != nil {
		t.Fatal("partial read fabricated an incomplete profile or lost the supported section")
	}
	_, response = request(t, s, path, `{"method":"get","video":{"name":["main","minor"]}}`)
	if response["error_code"] != float64(unsupportedCode) || response["video"] != nil {
		t.Fatal("a request with no usable profile was reported as successful")
	}
}

func TestMetadataServicesListImplementedVirtualListenersWithUPnPDisabled(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	body := `{"method":"get","cet":{"name":["rtsp","vhttpd","md5"]},"upnpc":{"table":["upnp_status"],"name":"upnpc_info"}}`
	_, response := request(t, s, path, body)
	if response["error_code"] != float64(0) {
		t.Fatal("combined service-port and UPnP read failed")
	}
	wantCET := map[string]any{"rtsp": map[string]any{"port": "554"}}
	if !reflect.DeepEqual(response["cet"], wantCET) {
		t.Fatal("CET exposed backend ports, donor authentication, or unimplemented services")
	}
	wantUPnP := map[string]any{"upnpc_info": map[string]any{"enabled": "off", "mode": "manual"}, "upnp_status": []any{
		map[string]any{"uhttpd": map[string]any{"ext_port": "443", "inner_port": "443", "ipaddr": "192.0.2.50", "status": "off"}},
		map[string]any{"rtsp": map[string]any{"ext_port": "554", "inner_port": "554", "ipaddr": "192.0.2.50", "status": "off"}},
	}}
	if !reflect.DeepEqual(response["upnpc"], wantUPnP) {
		t.Fatal("UPnP services lost the virtual IP, public port strings or disabled mapping status")
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &native); err != nil || !reflect.DeepEqual(native, response) {
		t.Fatal("native callback service discovery differs from HTTPS")
	}
}

func TestMetadataAdvertisesConfiguredRTSPDigest(t *testing.T) {
	s := testServer(t, func(cfg *Config) { cfg.RTSPDigest = true })
	path := login(t, s)
	_, response := request(t, s, path, `{"method":"get","cet":{"name":["rtsp","vhttpd"]}}`)
	want := map[string]any{"rtsp": map[string]any{"port": "554", "digest_auth_type": "MD5"}}
	if !reflect.DeepEqual(response["cet"], want) {
		t.Fatal("configured RTSP digest was omitted or unsupported vhttpd was advertised")
	}
}

func TestMetadataReadsDoNotEnableSettingsWrites(t *testing.T) {
	metadataCalls := 0
	s := testServer(t, func(cfg *Config) {
		cfg.Metadata = func() Metadata { metadataCalls++; return Metadata{SoftwareVersion: "fixture"} }
	})
	path := login(t, s)
	for _, body := range []string{
		`{"method":"set","device_info":{"basic_info":{"device_name":"changed"}}}`,
		`{"method":"set","video":{"main":{"resolution":"640*480"}}}`,
		`{"method":"set","cet":{"rtsp":{"port":"8554"}}}`,
		`{"method":"set","upnpc":{"upnpc_info":{"enabled":"on"}}}`,
	} {
		code, response := request(t, s, path, body)
		if code != http.StatusOK || !reflect.DeepEqual(response, map[string]any{"error_code": float64(unsupportedCode)}) {
			t.Fatal("metadata support enabled an unsupported settings write")
		}
		var native map[string]any
		if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &native); err != nil || !reflect.DeepEqual(native, response) {
			t.Fatal("native passthrough did not preserve write rejection")
		}
	}
	if metadataCalls != 0 {
		t.Fatal("a write invoked the read-only metadata provider")
	}
	_, response := request(t, s, path, `{"method":"get","device_info":{"name":"basic_info"}}`)
	info := metadataObject(t, metadataObject(t, response["device_info"])["basic_info"])
	if info["device_model"] != "AnyToOmada" || info["sw_version"] != "translator fixture" || strings.Contains(info["device_model"].(string), "Imou") {
		t.Fatal("unavailable source identity became a fabricated camera identity")
	}
}
