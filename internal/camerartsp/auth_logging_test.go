package camerartsp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/bluenviron/gortsplib/v5/pkg/base"
)

func TestAuthorizationFailureLogsOnlyFixedLabels(t *testing.T) {
	for _, tc := range []struct {
		name, target, wantMethod, wantProfile string
		method                                base.Method
	}{
		{"known", "rtsp://private-user:private-password@192.0.2.1/stream1/?token=private-token", "PLAY", "stream1", base.Play},
		{"unknown", "rtsp://192.0.2.1/private-path?token=private-token", "other", "other", base.Method("private-method")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := base.ParseURL(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			s := &Server{logger: slog.New(slog.NewJSONHandler(&output, nil))}
			request := &base.Request{Method: tc.method, URL: u, Header: base.Header{"Authorization": {
				`Digest username="private-user", realm="IPCAM", nonce="private-nonce", uri="rtsp://private-user:private-password@192.0.2.1/private-path?token=private-token", response="private-response", qop="auth", nc=00000001, cnonce="private-cnonce"`,
			}}}
			s.logAuthorizationFailure(request, "uri_mismatch")
			if strings.Contains(output.String(), "private-") {
				t.Fatal("authorization log retained client-supplied sensitive text")
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["method"] != tc.wantMethod || entry["profile"] != tc.wantProfile || entry["reason"] != "uri_mismatch" || entry["qop"] != true {
				t.Fatal("authorization log lost fixed diagnostic labels")
			}
			for key := range entry {
				switch key {
				case "time", "level", "msg", "method", "profile", "reason", "qop":
				default:
					t.Fatalf("unexpected authorization log field %q", key)
				}
			}
		})
	}
}
