package omadafront

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer(t *testing.T, options func(*Config)) *Server {
	t.Helper()
	cfg := Config{Username: "fixture-operator", Password: "synthetic-camera-password", IP: "192.0.2.50"}
	if options != nil {
		options(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(t *testing.T, s *Server, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return w.Code, value
}

func login(t *testing.T, s *Server) string {
	t.Helper()
	code, response := request(t, s, "/", `{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5"}}`)
	if code != http.StatusOK || response["error_code"] != float64(0) {
		t.Fatalf("login failed: status=%d", code)
	}
	token, ok := response["stok"].(string)
	if !ok || len(token) != 32 {
		t.Fatal("login did not generate a bounded token")
	}
	return "/stok=" + token + "/ds"
}

func TestObservedAuthenticationAndSelectors(t *testing.T) {
	s := testServer(t, nil)
	code, response := request(t, s, "/", `{"method":"do","user_management":{"get_encrypt_info":null}}`)
	if code != http.StatusUnauthorized || response["error_code"] != float64(-40401) {
		t.Fatal("incorrect observed challenge status")
	}
	challenge := response["data"].(map[string]any)
	if challenge["passwdType"] != "md5" || challenge["code"] != float64(-40407) {
		t.Fatal("incorrect observed challenge fields")
	}
	if _, ok := challenge["key"]; ok {
		t.Fatal("unimplemented RSA was advertised")
	}
	if types := challenge["encrypt_type"].([]any); len(types) != 1 || types[0] != "1" {
		t.Fatal("unimplemented encryption was advertised")
	}
	code, response = request(t, s, "/", `{"method":"do","get_rtsp_info":{}}`)
	if code != http.StatusOK || response["stream_num"] != float64(0) || response["ip_src_num"] != float64(0) {
		t.Fatal("incorrect RTSP discovery")
	}
	path := login(t, s)
	code, response = request(t, s, path, `{"method":"get","network":{"name":"wan_status"}}`)
	if code != http.StatusOK {
		t.Fatal("authenticated read failed")
	}
	wan := response["network"].(map[string]any)["wan_status"].(map[string]any)
	if wan["ipaddr"] != "192.0.2.50" {
		t.Fatal("proxy address was not reported")
	}
	_, response = request(t, s, path, `{"method":"get","function":{"name":"module_spec"}}`)
	spec := response["function"].(map[string]any)["module_spec"].(map[string]any)
	if spec["nvr_long_connect"] != "0" || spec["smart_detection"] != "0" || spec["msg_push"] != "0" {
		t.Fatal("unsupported native events were advertised")
	}
	codecs := spec["video_codec"].([]any)
	if len(codecs) != 2 || codecs[0] != "h264" || codecs[1] != "h265" || spec["stream_max_sessions"] != "8" {
		t.Fatal("implemented media capabilities were not reported")
	}
	if spec["stream_protocol"] != nil || spec["omada_ipc"] != "1.0" {
		t.Fatal("native protocol identity or implemented streaming advertisement is incorrect")
	}
}

func TestAnonymousRTSPDiscoveryAtEmptySessionPath(t *testing.T) {
	s := testServer(t, nil)
	// The captured NVR enrollment starts with an empty stok, before login at /.
	code, response := request(t, s, "/stok=/ds", `{"method":"do","get_rtsp_info":{}}`)
	if code != http.StatusOK || response["error_code"] != float64(0) || response["stream_num"] != float64(0) || response["ip_src_num"] != float64(0) {
		t.Fatal("empty-session RTSP discovery did not match the captured response")
	}
	if len(response) != 3 || s.Status().Sessions != 0 || s.Status().LoginSuccesses != 0 {
		t.Fatal("anonymous discovery exposed more than stream counts or created a session")
	}
}

func TestNetworkStatusReportsConfiguredVirtualMAC(t *testing.T) {
	for _, tc := range []struct {
		name string
		mac  [6]byte
		want string
	}{
		{"virtual identity", [6]byte{0x02, 0xa4, 0xb6, 0xc8, 0xda, 0xec}, "02-a4-b6-c8-da-ec"},
		{"another lens", [6]byte{0x02, 0xa4, 0xb6, 0xc8, 0xda, 0xed}, "02-a4-b6-c8-da-ed"},
		{"identity not provided", [6]byte{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Recreating the front with the same callback identity must report the
			// same bytes, using the captured management lowercase/hyphen format.
			for range 2 {
				s := testServer(t, func(cfg *Config) { cfg.MAC = tc.mac })
				code, response := request(t, s, "/stok=/ds", `{"method":"get","network":{"name":"wan_status"}}`)
				if code != http.StatusUnauthorized || response["network"] != nil {
					t.Fatal("virtual identity bypassed authenticated network reads")
				}
				path := login(t, s)
				code, response = request(t, s, path, `{"method":"get","network":{"name":"wan_status"}}`)
				if code != http.StatusOK || response["error_code"] != float64(0) {
					t.Fatal("authenticated virtual network read failed")
				}
				wan := response["network"].(map[string]any)["wan_status"].(map[string]any)
				mac, present := wan["mac"]
				if tc.want == "" {
					if present {
						t.Fatal("missing virtual identity was replaced with a fabricated MAC")
					}
				} else if !present || mac != tc.want {
					t.Fatal("management MAC did not preserve the configured virtual identity")
				}
				if wan["ipaddr"] != "192.0.2.50" || wan["proto"] != "static" || wan["error_code"] != float64(0) {
					t.Fatal("adding virtual MAC changed other network fields")
				}
			}
		})
	}
}

func TestAnonymousRTSPDiscoveryAcceptsJSONWhitespace(t *testing.T) {
	// The genuine enrollment probe pretty-prints the empty object. JSON
	// whitespace must not turn an anonymous stream-count read into a challenge.
	for _, path := range []string{"/", "/stok=/ds"} {
		for _, body := range []string{
			"{\n\t\"method\": \"do\",\n\t\"get_rtsp_info\": {\n\t}\n}",
			"{\"get_rtsp_info\": { \r\n\t }, \"method\":\"do\"}",
		} {
			s := testServer(t, nil)
			code, response := request(t, s, path, body)
			if code != http.StatusOK || response["error_code"] != float64(0) || response["stream_num"] != float64(0) || response["ip_src_num"] != float64(0) || len(response) != 3 {
				t.Fatal("whitespace-formatted discovery did not return only stream counts")
			}
			if status := s.Status(); status.Sessions != 0 || status.LoginSuccesses != 0 || status.LoginFailures != 0 {
				t.Fatal("anonymous discovery changed authentication state")
			}
		}
	}
}

func TestAnonymousDiscoveryDoesNotAuthorizeOtherOperations(t *testing.T) {
	s := testServer(t, nil)
	for _, body := range []string{
		`{"method":"get","network":{"name":"wan_status"}}`,
		`{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"192.0.2.60","port":6000,"auth_code":"synthetic-private-proof"}}}`,
		`{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5"}}`,
		`{"method":"do","get_rtsp_info":{},"network":{"name":"wan_status"}}`,
		`{"method":"do","get_rtsp_info":{"unexpected":true}}`,
		`{"method":"do","get_rtsp_info":null}`,
		`{"method":"do","get_rtsp_info":[]}`,
		`{"method":"do","get_rtsp_info":"{}"}`,
		`{"method":"do","get_rtsp_info":false}`,
		`{"method":"do","get_rtsp_info":0}`,
		`{"method":"get","get_rtsp_info":{}}`,
	} {
		code, response := request(t, s, "/stok=/ds", body)
		if code != http.StatusUnauthorized || response["error_code"] != float64(unauthorizedCode) || response["stream_num"] != nil {
			t.Fatal("empty-session discovery bypassed authentication for another operation")
		}
	}
	for _, path := range []string{"/stok=invalid/ds", "/stok=/ds/extra", "/stok=/ds?unexpected=1"} {
		code, response := request(t, s, path, `{"method":"do","get_rtsp_info":{}}`)
		if code == http.StatusOK || response["stream_num"] != nil {
			t.Fatal("anonymous discovery accepted an unobserved session path")
		}
	}
	if s.Status().Sessions != 0 || s.Status().LoginSuccesses != 0 {
		t.Fatal("empty-session operations created a session")
	}
}

func TestRejectedCredentialsAndExpiredSessions(t *testing.T) {
	s := testServer(t, nil)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	for _, body := range []string{
		`{"method":"do","login":{"username":"fixture-operator","password":"synthetic-camera-password","passwdType":"md5"}}`,
		`{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"sha256"}}`,
		`{"method":"do","login":{"username":"wrong","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5"}}`,
		`{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5","encrypt_type":"2"}}`,
	} {
		code, _ := request(t, s, "/", body)
		if code != http.StatusUnauthorized {
			t.Fatal("invalid credentials or scheme accepted")
		}
	}
	path := login(t, s)
	clock = clock.Add(15 * time.Minute)
	code, _ := request(t, s, path, `{"method":"get","network":{"name":"wan_status"}}`)
	if code != http.StatusUnauthorized || s.Status().Sessions != 0 {
		t.Fatal("expired session accepted or retained")
	}
	if s.Status().LoginFailures != 4 {
		t.Fatal("missing failed-login counters")
	}
}

func TestSessionBoundDoesNotEvictExistingClient(t *testing.T) {
	s := testServer(t, func(c *Config) { c.MaxSessions = 1 })
	path := login(t, s)
	code, response := request(t, s, "/", `{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5"}}`)
	if code != http.StatusServiceUnavailable || response["stok"] != nil {
		t.Fatal("session cap exceeded")
	}
	code, _ = request(t, s, path, `{"method":"get","system":{"name":"time_status"}}`)
	if code != http.StatusOK || s.Status().Sessions != 1 {
		t.Fatal("existing session was evicted")
	}
}

func TestNoFalseSuccessForNativeCallbackOrWrites(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	for _, body := range []string{
		`{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"192.0.2.60","port":6000,"auth_code":"synthetic-private-proof"}}}`,
		`{"method":"set","system":{"basic":{"timezone":"synthetic-zone"}}}`,
		`{"method":"do","system":{"set_time":{"T1_timestramp":123}}}`,
		`{"method":"do","video":{"force_iframe":{"stream_type":"main"}}}`,
		`{"method":"get","smart_analysis":{"name":"capability"}}`,
		`{"method":"do","synthetic-private-proof":{"password":"must-not-be-retained"}}`,
	} {
		code, response := request(t, s, path, body)
		if code != http.StatusOK || response["error_code"] != float64(-40106) {
			t.Fatal("unsupported behavior reported success")
		}
	}
	status, err := json.Marshal(s.Status())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-private-proof", "must-not-be-retained", "48A884BED8D6C46E9DC303655C804B0A", path} {
		if strings.Contains(string(status), secret) {
			t.Fatal("status leaked private input")
		}
	}
	if s.Status().Unsupported["nvr_long_connect"] != 1 {
		t.Fatal("missing callback refusal counter")
	}
	detached := s.Status()
	detached.Unsupported["nvr_long_connect"] = 999
	if s.Status().Unsupported["nvr_long_connect"] != 1 {
		t.Fatal("status map aliases internal state")
	}
}

func TestBoundedParsingAndAuthorization(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	for _, body := range []string{`null`, `{`, `{"method":"get"} {}`, `{"method":3}`, `{"method":"do","data":"` + strings.Repeat("x", maxBodyBytes) + `"}`} {
		code, _ := request(t, s, path, body)
		if code != http.StatusBadRequest {
			t.Fatal("malformed or oversized request accepted")
		}
	}
	for _, target := range []string{"/", "/stok=not-a-token/ds", path + "/extra"} {
		code, _ := request(t, s, target, `{"method":"get","network":{"name":"wan_status"}}`)
		if code != http.StatusUnauthorized {
			t.Fatal("unauthenticated read succeeded")
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("HTTP GET accepted")
	}
}

func TestConcurrentReadsAndStatus(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			for range 20 {
				request(t, s, path, `{"method":"get","network":{"name":"wan_status"}}`)
				_ = s.Status()
			}
		})
	}
	group.Wait()
	if s.Status().Requests != 401 {
		t.Fatal("lost concurrent request counters")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, modify := range []func(*Config){
		func(c *Config) { c.Username = "" }, func(c *Config) { c.Password = "" },
		func(c *Config) { c.IP = "0.0.0.0" }, func(c *Config) { c.IP = "224.0.0.1" },
		func(c *Config) { c.IP = "secret-not-an-address" }, func(c *Config) { c.SessionTTL = time.Second },
		func(c *Config) { c.SessionTTL = 2 * time.Hour }, func(c *Config) { c.MaxSessions = 257 },
	} {
		cfg := Config{Username: "fixture", Password: "fixture", IP: "192.0.2.50"}
		modify(&cfg)
		if _, err := New(cfg); err == nil || strings.Contains(err.Error(), "secret-not-an-address") {
			t.Fatal("invalid configuration accepted or leaked")
		}
	}
}
