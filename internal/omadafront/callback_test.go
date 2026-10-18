package omadafront

import (
	"errors"
	"net/http"
	"testing"
)

func TestCallbackRegistrationRequiresAuthenticationAndRealWorker(t *testing.T) {
	var got CallbackRequest
	calls := 0
	s := testServer(t, func(c *Config) { c.StartCallback = func(r CallbackRequest) error { got = r; calls++; return nil } })
	body := `{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"192.0.2.150","port":6000,"version":"0101000101","auth_code":"synthetic-registration-code"}}}`
	code, _ := request(t, s, "/stok=/ds", body)
	if code != http.StatusUnauthorized || calls != 0 {
		t.Fatal("anonymous callback registration started a worker")
	}
	path := login(t, s)
	code, response := request(t, s, path, body)
	if code != http.StatusOK || response["error_code"] != float64(0) || response["version"] != "0101000101" || calls != 1 || got.IP != "192.0.2.150" || got.Port != 6000 || got.AuthCode != "synthetic-registration-code" {
		t.Fatal("authenticated registration contract mismatch")
	}
	_, response = request(t, s, path, `{"method":"get","function":{"name":"module_spec"}}`)
	if response["function"].(map[string]any)["module_spec"].(map[string]any)["nvr_long_connect"] != "1.0" {
		t.Fatal("callback capability absent with worker")
	}
	s.startCallback = func(CallbackRequest) error { return errors.New("worker stopped") }
	_, response = request(t, s, path, body)
	if response["error_code"] == float64(0) {
		t.Fatal("failed registration acknowledged success")
	}
}

func TestCallbackRegistrationRejectsMalformedParameters(t *testing.T) {
	calls := 0
	s := testServer(t, func(c *Config) { c.StartCallback = func(CallbackRequest) error { calls++; return nil } })
	path := login(t, s)
	for _, parameters := range []string{
		`{"ip":"example.invalid","port":6000,"version":"0101000101","auth_code":"test"}`,
		`{"ip":"192.0.2.150","port":0,"version":"0101000101","auth_code":"test"}`,
		`{"ip":"192.0.2.150","port":6000,"version":"unknown","auth_code":"test"}`,
		`{"ip":"192.0.2.150","port":6000,"version":"0101000101","auth_code":""}`,
		`{"ip":"192.0.2.150","port":6000,"version":"0101000101","auth_code":"test","unknown":true}`,
	} {
		_, response := request(t, s, path, `{"method":"do","nvr_long_connect":{"nvr_connect_start":`+parameters+`}}`)
		if response["error_code"] == float64(0) {
			t.Fatal("malformed registration accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid registration reached callback worker")
	}
}

func TestCallbackStopUsesOnlyRequestedRecorderEndpoint(t *testing.T) {
	stopped := false
	s := testServer(t, func(c *Config) {
		c.StartCallback = func(CallbackRequest) error { return nil }
		c.StopCallback = func(ip string, port int) { stopped = ip == "192.0.2.150" && port == 6000 }
	})
	path := login(t, s)
	_, response := request(t, s, path, `{"method":"do","nvr_long_connect":{"nvr_connect_stop":{"ip":"192.0.2.150","port":6000}}}`)
	if !stopped || response["error_code"] != float64(0) {
		t.Fatal("stop did not use observed endpoint contract")
	}
}
