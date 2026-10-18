package omadafront

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestSessionTokensAreFresh32CharacterHex(t *testing.T) {
	s := testServer(t, nil)
	first, second := login(t, s), login(t, s)
	if first == second {
		t.Fatal("separate logins reused a session token")
	}
	for _, path := range []string{first, second} {
		token := strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds")
		decoded, err := hex.DecodeString(token)
		if err != nil || len(token) != 32 || len(decoded) != 16 || token != strings.ToLower(token) {
			t.Fatal("session did not contain 128 random bits encoded as 32 hex characters")
		}
		code, _ := request(t, s, path, `{"method":"get","network":{"name":"wan_status"}}`)
		if code != http.StatusOK {
			t.Fatal("new session could not authorize a management read")
		}
		code, _ = request(t, s, "/stok="+token+token+"/ds", `{"method":"get","network":{"name":"wan_status"}}`)
		if code != http.StatusUnauthorized {
			t.Fatal("incorrect-length session path was accepted")
		}
	}
}

func TestRequestDiagnosticsRecordEnrollmentSequenceWithoutPrivateFields(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil)).With("camera_id", "fixture-camera")
	s := testServer(t, func(cfg *Config) { cfg.Logger = logger })
	callback := `{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"192.0.2.60","port":6000,"auth_code":"private-callback-proof"}}}`
	request(t, s, "/stok=/ds", `{"method":"do","get_rtsp_info":{}}`)
	request(t, s, "/stok=/ds", callback)
	request(t, s, "/stok=/ds", `{"method":"do","user_management":{"get_encrypt_info":null}}`)
	path := login(t, s)
	request(t, s, path, callback)
	request(t, s, path, `{"method":"get","function":{"name":"module_spec"}}`)
	request(t, s, path, `{"method":"do","private-module-name":{"private-field":"private-payload-value"}}`)
	request(t, s, "/", `{"method":"do","login":{"username":"fixture-operator","password":"private-rejected-password","passwdType":"md5"}}`)
	request(t, s, path, `{"private-malformed-body"`)
	request(t, s, path+"?private-query=value", `{"method":"get","network":{"name":"wan_status"}}`)

	for _, private := range []string{
		"synthetic-camera-password", "fixture-operator", "48A884BED8D6C46E9DC303655C804B0A",
		"private-callback-proof", "private-module-name", "private-field", "private-payload-value",
		"private-rejected-password", "private-malformed-body", "private-query", "auth_code", "nonce", "stok",
		strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds"),
	} {
		if strings.Contains(output.String(), private) {
			t.Fatal("request diagnostics contained private request or session data")
		}
	}
	expected := []struct {
		operation, auth string
		status, code    int
	}{
		{"stream_discovery", "anonymous", 200, 0},
		{"callback_registration", "required", 401, unauthorizedCode},
		{"auth_challenge", "required", 401, unauthorizedCode},
		{"login", "accepted", 200, 0},
		{"callback_registration", "authenticated", 200, unsupportedCode},
		{"capabilities", "authenticated", 200, 0},
		{"unknown", "authenticated", 200, unsupportedCode},
		{"login", "rejected", 401, unauthorizedCode},
		{"unknown", "not_checked", 400, unsupportedCode},
		{"unknown", "not_checked", 404, unsupportedCode},
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != len(expected) {
		t.Fatal("request diagnostics did not emit exactly one entry per request")
	}
	allowedFields := map[string]bool{"time": true, "level": true, "msg": true, "camera_id": true, "operation": true, "auth_outcome": true, "http_status": true, "error_code": true, "path_kind": true, "discovery_shape": true, "request_shape": true}
	for i, line := range lines {
		var fields map[string]any
		if err := json.Unmarshal(line, &fields); err != nil {
			t.Fatal("request diagnostics were not JSON")
		}
		for name := range fields {
			if !allowedFields[name] {
				t.Fatal("request diagnostics emitted an unexpected field")
			}
		}
		want := expected[i]
		if fields["operation"] != want.operation || fields["auth_outcome"] != want.auth || fields["http_status"] != float64(want.status) || fields["error_code"] != float64(want.code) || fields["camera_id"] != "fixture-camera" || fields["msg"] != "camera management request" {
			t.Fatalf("request diagnostic sequence mismatch at entry %d", i)
		}
	}
	if s.Status().Unsupported["nvr_long_connect"] != 1 || s.Status().NativeEventsImplemented {
		t.Fatal("diagnostics changed the unsupported callback contract")
	}
}

func TestRequestDiagnosticsClassifyDiscoveryWithoutLoggingPaths(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, pathKind, shape string
		status                            int
	}{
		{"root", "/", `{"method":"do","get_rtsp_info":{ }}`, "root", "empty_object", 200},
		{"empty session", "/stok=/ds", "{\"method\":\"do\",\"get_rtsp_info\":{\n\t}}", "empty_session", "empty_object", 200},
		{"unknown session", "/stok=private-session-value/ds", `{"method":"do","get_rtsp_info":{}}`, "session", "empty_object", 401},
		{"invalid shape", "/stok=/ds", `{"method":"do","get_rtsp_info":{"private-key":"private-value"}}`, "empty_session", "other", 401},
		{"null", "/stok=/ds", `{"method":"do","get_rtsp_info":null}`, "empty_session", "other", 401},
		{"unknown route", "/private-route", `{"method":"do","get_rtsp_info":{}}`, "other", "not_applicable", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
			status, _ := request(t, s, tc.path, tc.body)
			var fields map[string]any
			if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if status != tc.status || fields["path_kind"] != tc.pathKind || fields["discovery_shape"] != tc.shape {
				t.Fatal("incorrect fixed request classifications or response")
			}
			if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), "stok") {
				t.Fatal("request diagnostics leaked a path, field or value")
			}
		})
	}
}

func TestUnsupportedReadDiagnosticsClassifyKnownModulesWithoutChangingResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		labels     []string
	}{
		{"array selector", `{"method":"get","ai_enhance_capability":{"name":["traditional_enhance"]}}`, []string{"ai_enhancement_capability"}},
		{"multiple modules", `{"method":"get","light_control":{"name":"light_alarm_info"},"light_alarm_info_capability":{"name":"capability"}}`, []string{"light_capability", "light_configuration"}},
		{"unsupported schedule and tables", `{"method":"get","linecrossing_detection":{"version":"1","name":["sound_alarm_info"],"table":["unknown_table"]},"msg_alarm_plan":{"name":["arming_schedule_sound","arming_schedule_light"]}}`, []string{"alarm_schedule", "line_crossing_detection"}},
		{"unknown and private values", `{"method":"get","private-module-secret":{"name":"private-selector-secret","password":"private-body-secret"},"motion_detection":{"private-field-secret":"private-payload-secret"}}`, []string{"motion_detection", "unknown"}},
		{"unknown only", `{"method":"get","private-module-secret":null}`, []string{"unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
			path := login(t, s)
			output.Reset()
			code, response := request(t, s, path, tc.body)
			if code != http.StatusOK || len(response) != 1 || response["error_code"] != float64(unsupportedCode) {
				t.Fatal("module diagnostics changed the unsupported response")
			}
			var fields struct {
				Operation   string   `json:"operation"`
				AuthOutcome string   `json:"auth_outcome"`
				ReadModules []string `json:"read_modules"`
			}
			if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if fields.Operation != "unsupported_read" || fields.AuthOutcome != "authenticated" || !slices.Equal(fields.ReadModules, tc.labels) {
				t.Fatal("unsupported read did not emit the expected fixed module labels")
			}
			token := strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds")
			for _, private := range []string{"private-", "password", "stok", token, tc.body} {
				if strings.Contains(output.String(), private) {
					t.Fatal("unsupported read diagnostics exposed a private key, body or session")
				}
			}
			if s.Status().Unsupported["unsupported_read"] != 1 || s.Status().Sessions != 1 {
				t.Fatal("module diagnostics changed request or session accounting")
			}
		})
	}
}

func TestUnsupportedReadDiagnosticsRemainBoundedAndSorted(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
	path := login(t, s)
	output.Reset()
	body := map[string]any{"method": "get"}
	for _, module := range []string{"system", "network", "function", "video", "motion_detection", "tamper_detection", "intrusion_detection", "linecrossing_detection", "msg_alarm", "pet_detection", "audio_config"} {
		body[module] = map[string]string{"name": "private-selector-secret"}
	}
	for i := range 1000 {
		body["private-module-secret-"+strconv.Itoa(i)] = "private-body-secret"
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= maxBodyBytes {
		t.Fatal("fixture exceeded the request bound")
	}
	code, response := request(t, s, path, string(encoded))
	if code != http.StatusOK || response["error_code"] != float64(unsupportedCode) {
		t.Fatal("large module set changed the unsupported response")
	}
	var fields struct {
		ReadModules []string `json:"read_modules"`
	}
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields.ReadModules) != 8 || !slices.IsSorted(fields.ReadModules) || !slices.Contains(fields.ReadModules, "truncated") || !slices.Contains(fields.ReadModules, "unknown") {
		t.Fatal("module diagnostics lost their sorted bound or omission markers")
	}
	if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), "stok") {
		t.Fatal("bounded module diagnostics exposed unrecognized input")
	}
}

func TestReadModuleDiagnosticsDoNotBroadenAuthenticationOrWrites(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
	code, response := request(t, s, "/stok=/ds", `{"method":"get","motion_detection":{"name":["motion_det"]}}`)
	if code != http.StatusUnauthorized || response["error_code"] != float64(unauthorizedCode) || s.Status().Sessions != 0 {
		t.Fatal("known module classification bypassed authentication")
	}
	path := login(t, s)
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"method":"get","network":{"name":"wan_status"}}`, 0},
		{`{"method":"set","motion_detection":{"enabled":true}}`, unsupportedCode},
		{`{"method":"do","video":{"force_iframe":{"stream_type":"main"}}}`, unsupportedCode},
	} {
		output.Reset()
		code, response := request(t, s, path, tc.body)
		if code != http.StatusOK || response["error_code"] != float64(tc.code) {
			t.Fatal("module diagnostics changed a supported read or unsupported write")
		}
		var fields map[string]any
		if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		if _, found := fields["read_modules"]; found {
			t.Fatal("module labels were emitted outside an unsupported read")
		}
	}
}
