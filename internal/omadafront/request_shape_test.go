package omadafront

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPSUnknownPTZLogsShapeWithoutValues(t *testing.T) {
	var output bytes.Buffer
	s := testServer(t, func(cfg *Config) {
		cfg.Logger = slog.New(slog.NewJSONHandler(&output, nil))
	})
	path := login(t, s)
	output.Reset()
	code, response := request(t, s, path, `{"method":"do","ptz":{"opt_quick_tour":{"tour_name":"private-tour","password":{"private_label":"private-value"}}}}`)
	if code != http.StatusOK || response["error_code"] != float64(unsupportedCode) {
		t.Fatalf("unexpected response: %d %v", code, response)
	}
	var fields struct {
		Shape []string `json:"request_shape"`
	}
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields.Shape, []string{"ptz.opt_quick_tour{redacted,tour_name}"}) {
		t.Fatalf("request shape = %v", fields.Shape)
	}
	for _, private := range []string{"private", "password", path} {
		if strings.Contains(output.String(), private) {
			t.Fatal("request diagnostics contain a private value")
		}
	}
}
