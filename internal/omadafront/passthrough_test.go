package omadafront

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPassthroughReadsMatchAuthenticatedHTTP(t *testing.T) {
	s := testServer(t, nil)
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	path := login(t, s)
	for _, body := range []string{
		`{"method":"get","network":{"name":"wan_status"}}`,
		`{"method":"get","function":{"name":"module_spec"}}`,
		`{"method":"get","system":{"name":"time_status"}}`,
	} {
		_, expected := request(t, s, path, body)
		var actual map[string]any
		if err := json.Unmarshal(s.Passthrough(json.RawMessage(body)), &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("native management diverged from the existing HTTP read")
		}
	}
}

func TestPassthroughRejectsWritesAndDoesNotCreateSessionsOrCallbacks(t *testing.T) {
	started := false
	s := testServer(t, func(cfg *Config) {
		cfg.StartCallback = func(CallbackRequest) error { started = true; return nil }
	})
	for _, body := range []string{
		`{"method":"set","system":{"time_status":{"seconds_from_1970":0}}}`,
		`{"method":"do","system":{"reboot":null}}`,
		`{"method":"do","nvr_long_connect":{"nvr_connect_start":{}}}`,
		`{"method":"do","login":{"username":"fixture-operator"}}`,
		`{"method":"get","unknown":{"name":"unknown"}}`,
		`"encoded-string"`, `null`, `[]`, `{`,
		`{"method":"get","network":{"name":"wan_status"}} {}`,
		strings.Repeat(" ", maxBodyBytes+1),
	} {
		if string(s.Passthrough(json.RawMessage(body))) != `{"error_code":-40106}` {
			t.Fatal("unsupported native request was accepted")
		}
	}
	if started || s.Status().Sessions != 0 || s.Status().LoginSuccesses != 0 {
		t.Fatal("native read dispatcher created an authentication or callback session")
	}
}

func TestPassthroughDiagnosticsExposeSelectorsWithoutPrivateValues(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) { cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil)) })
	s.Passthrough(json.RawMessage(`{"method":"get","device_info":{"name":"basic_info","password":"private-value"},"private-module":{"name":"private-selector"}}`))
	var fields struct {
		Message   string   `json:"msg"`
		Selectors []string `json:"read_selectors"`
		ErrorCode int      `json:"error_code"`
	}
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields.Message != "native management request" || fields.ErrorCode != unsupportedCode ||
		!reflect.DeepEqual(fields.Selectors, []string{"device_info.name:basic_info", "unknown"}) {
		t.Fatal("missing bounded native request diagnostics")
	}
	if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), "password") {
		t.Fatal("native request diagnostics exposed private input")
	}
}
