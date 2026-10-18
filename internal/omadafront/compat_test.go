package omadafront

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func compatMetadata() Metadata {
	return Metadata{Name: "fixture-lens", Brand: "Imou", Model: "IPC-fixture", Firmware: "2.680.fixture.R", BuildDate: "2024-12-02", SoftwareVersion: "test-translator",
		Video: map[string]VideoMetadata{
			"main":  {Codec: "H265", Width: 1920, Height: 1080, BitrateKbps: 1024, BitrateMode: "cbr", FrameRateNumerator: 25, FrameRateDenominator: 1},
			"minor": {Codec: "H264", Width: 640, Height: 480, BitrateKbps: 512, BitrateMode: "cbr", FrameRateNumerator: 25, FrameRateDenominator: 1},
		}}
}

const compatRead = `{"method":"get","function":{"name":"module_spec"},"network":{"name":"wan_status"},"video":{"name":["main","minor"]},"device_info":{"name":["basic_info","info"]},"cet":{"name":["rtsp","vhttpd"]},"upnpc":{"table":"upnp_status","name":"upnpc_info"}}`

func TestCompatibilityDefaultsKeepImplementedContract(t *testing.T) {
	s := testServer(t, func(cfg *Config) { cfg.Metadata = compatMetadata; cfg.RTSPDigest = true })
	path := login(t, s)
	_, response := request(t, s, path, compatRead)
	spec := metadataObject(t, metadataObject(t, response["function"])["module_spec"])
	wan := metadataObject(t, metadataObject(t, response["network"])["wan_status"])
	main := metadataObject(t, metadataObject(t, response["video"])["main"])
	basic := metadataObject(t, metadataObject(t, response["device_info"])["basic_info"])
	info := metadataObject(t, metadataObject(t, response["device_info"])["info"])
	cet := metadataObject(t, response["cet"])
	rows := metadataObject(t, response["upnpc"])["upnp_status"].([]any)
	if spec["media_encrypt"] != nil || len(spec) > 12 || wan["gateway"] != nil || main["smart_codec"] != nil ||
		basic["hw_version"] != nil || info["sn"] != nil || cet["vhttpd"] != nil || len(rows) != 2 || basic["manufacturer_name"] != "AnyToOmada" {
		t.Fatal("disabled compatibility options changed the implemented contract")
	}
	if basic["device_model"] != "Imou IPC-fixture · AnyToOmada" {
		t.Fatal("HTTPS strings were encoded without the option")
	}
}

func TestCompatibilityOptionsShapeResponsesLikeTheObservedCamera(t *testing.T) {
	s := testServer(t, func(cfg *Config) {
		cfg.Metadata = compatMetadata
		cfg.RTSPDigest = true
		cfg.StartCallback = func(CallbackRequest) error { return nil }
		cfg.Compatibility = Compatibility{ObservedModuleSpec: true, AdvertiseVHTTPD: true, ExtendedVideoFields: true, ExtendedIdentity: true,
			ManufacturerName: "Fixture-Vendor", Netmask: "255.255.255.0", Gateway: "192.0.2.1", DNS: "192.0.2.1"}
	})
	path := login(t, s)
	_, response := request(t, s, path, compatRead)
	spec := metadataObject(t, metadataObject(t, response["function"])["module_spec"])
	if spec["media_encrypt"] != "1" || spec["nvr_long_connect"] != "1.0" || spec["omada_ipc"] != "1.0" || spec["stream_max_sessions"] != "8" ||
		spec["change_password"] != nil || spec["verification_change_password"] != nil || len(spec) < 120 {
		t.Fatal("observed module_spec profile is incomplete, invents redacted members or loses the translator's own limits")
	}
	wan := metadataObject(t, metadataObject(t, response["network"])["wan_status"])
	if wan["netmask"] != "255.255.255.0" || wan["gateway"] != "192.0.2.1" || wan["pri_dns"] != "192.0.2.1" || wan["snd_dns"] != "0.0.0.0" ||
		wan["internet_status"] != float64(0) || wan["pppoe_ipv4"] != "0.0.0.0" || wan["link_status"] != float64(1) {
		t.Fatal("extended network status is missing donor fields or integer types")
	}
	video := metadataObject(t, response["video"])
	main, minor := metadataObject(t, video["main"]), metadataObject(t, video["minor"])
	if main["smart_codec"] != "off" || main["adaptive_mode"] != "off" || main["default_bitrate"] != "1024" || main["socialshare_auto_h264"] != nil ||
		minor["socialshare_auto_h264"] != "0" || minor["smart_codec"] != nil || main["resolution"] != "1920*1080" {
		t.Fatal("extended video fields are wrong or changed source facts")
	}
	identity := metadataObject(t, response["device_info"])
	basic, info := metadataObject(t, identity["basic_info"]), metadataObject(t, identity["info"])
	if basic["hw_version"] != "1.0" || basic["features"] != float64(3) || basic["region"] != "UN" || basic["imei"] != "" || basic["passwdType"] != "md5" ||
		basic["device_info"] != "Imou IPC-fixture · AnyToOmada 1.0 IPC" || basic["manufacturer_name"] != "Fixture-Vendor" {
		t.Fatal("extended basic identity is incomplete")
	}
	for field, length := range map[string]int{"barcode": 20, "dev_id": 40, "hw_id": 32, "fw_cur_id": 32, "oem_id": 32} {
		value, _ := basic[field].(string)
		if len(value) != length || strings.ToUpper(value) != value {
			t.Fatalf("virtual identifier %s has unexpected shape", field)
		}
	}
	serial, _ := info["sn"].(string)
	if info["hw_version"] != "1.0" || info["model_description"] != "IPC" || info["devcode"] != basic["barcode"] || !strings.HasPrefix(serial, "ATO") || len(serial) != 13 ||
		info["cover_reg_num"] != float64(4) || info["md_reg_num"] != float64(32) || info["roi_reg_num"] != float64(0) || info["isp_version"] != float64(1) || info["isp_sw_version"] != info["sw_version"] {
		t.Fatal("extended info identity is incomplete")
	}
	if virtualIdentifier("fixture-lens", "serial", 10) != serial[3:] || virtualIdentifier("other-lens", "serial", 10) == serial[3:] {
		t.Fatal("virtual identifiers are not stable per camera name")
	}
	cet := metadataObject(t, response["cet"])
	if !reflect.DeepEqual(cet["vhttpd"], map[string]any{"port": "8800", "digest_auth_type": "MD5"}) || !reflect.DeepEqual(cet["rtsp"], map[string]any{"port": "554", "digest_auth_type": "MD5"}) {
		t.Fatal("advertised services differ from the observed CET shape")
	}
	rows := metadataObject(t, response["upnpc"])["upnp_status"].([]any)
	names := []string{}
	for _, row := range rows {
		for name, body := range metadataObject(t, row) {
			names = append(names, name)
			if fields := metadataObject(t, body); fields["ipaddr"] != "192.0.2.50" || fields["status"] != "off" {
				t.Fatal("UPnP row lost the virtual IP or disabled status")
			}
		}
	}
	if !reflect.DeepEqual(names, []string{"uhttpd", "rtsp", "onvif_service", "vhttpd", "vhttpsd"}) {
		t.Fatal("UPnP rows differ from the observed service order")
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(compatRead)), &native); err != nil {
		t.Fatal(err)
	}
	if native["cet"] == nil || metadataObject(t, native["cet"])["vhttpd"] == nil {
		t.Fatal("native passthrough did not share the compatibility view")
	}
}

func TestCompatibilityEncodesHTTPStringsLikeTheNativeCamera(t *testing.T) {
	s := testServer(t, func(cfg *Config) {
		cfg.Metadata = compatMetadata
		cfg.Compatibility = Compatibility{EncodeHTTPStrings: true}
	})
	path := login(t, s)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"method":"get","device_info":{"name":"basic_info"},"video":{"name":"main"}}`))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || strings.Contains(body, "Imou IPC") || !strings.Contains(body, "Imou%20IPC-fixture%20%c2%b7%20AnyToOmada") || !strings.Contains(body, `"1920*1080"`) {
		t.Fatalf("HTTPS strings were not encoded with the native alphabet: %s", body)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(body), &response); err != nil || response["error_code"] != float64(0) {
		t.Fatal("encoded response is not valid JSON with a numeric error code")
	}
	model, _ := metadataObject(t, metadataObject(t, response["device_info"])["basic_info"])["device_model"].(string)
	if decoded, err := url.PathUnescape(model); err != nil || decoded != "Imou IPC-fixture · AnyToOmada" {
		t.Fatal("encoded string does not decode to the original value")
	}
	if w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("X-Frame-Options") != "SAMEORIGIN" || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("response headers differ from the captured native camera")
	}
	code, challenge := request(t, s, "/", `{"method":"do","user_management":{"get_encrypt_info":null}}`)
	if code != http.StatusUnauthorized || challenge["error_code"] != float64(-40401) || challenge["device_type"] != "SECUR.CONSUMER.IPC" {
		t.Fatal("encoding changed the challenge contract")
	}
}

func TestObservedProfileAnswersClassificationCapabilityReads(t *testing.T) {
	plain := testServer(t, nil)
	path := login(t, plain)
	for _, body := range []string{
		`{"method":"get","ai_enhance_capability":{"name":["traditional_enhance"]}}`,
		`{"method":"get","linkage_capability":{"name":"capability"}}`,
	} {
		if _, response := request(t, plain, path, body); response["error_code"] != float64(unsupportedCode) {
			t.Fatalf("minimal profile answered %s", body)
		}
	}
	_, response := request(t, plain, path, `{"method":"get","smart_detection":{"name":"capability"}}`)
	if metadataObject(t, metadataObject(t, response["smart_detection"])["capability"])["smart_data"] != "0" {
		t.Fatal("minimal profile reported smart data")
	}
	observed := testServer(t, func(cfg *Config) { cfg.Compatibility = Compatibility{ObservedModuleSpec: true} })
	path = login(t, observed)
	_, response = request(t, observed, path, `{"method":"get","ai_enhance_capability":{"name":["traditional_enhance"]},"linkage_capability":{"name":"capability"},"smart_detection":{"name":"capability"}}`)
	enhance := metadataObject(t, metadataObject(t, response["ai_enhance_capability"])["traditional_enhance"])
	linkage := metadataObject(t, metadataObject(t, response["linkage_capability"])["capability"])
	smart := metadataObject(t, metadataObject(t, response["smart_detection"])["capability"])
	if enhance["people_enhance_ver"] != "7" || linkage["record_capability"] != "010000000001000101100000000000001111" || len(linkage) != 7 ||
		smart["smart_data"] != "1" || smart["intrusion_detection"] != "1" || smart["linecrossing_detection"] != "1" {
		t.Fatal("observed profile classification capability answers differ from the Omada camera")
	}
}
