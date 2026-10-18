package omadafront

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestVirtualTimeWritesRequireAuthenticationAndShareNativeState(t *testing.T) {
	s := testServer(t, nil)
	body := `{"method":"set","system":{"basic":{"timezone":"UTC+02:00","zone_id":"Europe/Vilnius","date_format":1,"time_format":0}}}`
	code, _ := request(t, s, "/stok=/ds", body)
	if code != http.StatusUnauthorized || timeSection(t, s.virtualTime, "basic")["timezone"] != "UTC+00:00" {
		t.Fatal("unauthenticated settings changed virtual time state")
	}
	path := login(t, s)
	code, response := request(t, s, path, body)
	if code != http.StatusOK || response["error_code"] != float64(0) {
		t.Fatal("authenticated virtual time configuration failed")
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"get","system":{"name":"basic"}}`)), &native); err != nil {
		t.Fatal(err)
	}
	basic := metadataObject(t, metadataObject(t, native["system"])["basic"])
	if basic["timezone"] != "UTC+02:00" || basic["zone_id"] != "Europe/Vilnius" {
		t.Fatal("callback read did not observe HTTPS virtual settings")
	}
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"set","system":{"basic":{"time_format":1}}}`)), &native); err != nil || native["error_code"] != float64(0) {
		t.Fatal("authenticated callback could not update virtual time presentation")
	}
	_, response = request(t, s, path, `{"method":"get","system":{"name":"basic"}}`)
	basic = metadataObject(t, metadataObject(t, response["system"])["basic"])
	if basic["time_format"] != float64(1) || basic["timezone"] != "UTC+02:00" {
		t.Fatal("HTTPS read did not preserve the merged callback settings")
	}
}
