package app

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

// The recorder can send two passthrough requests before either Auth answer.
// Both challenges must remain valid even when the answers arrive out of order.
func TestCallbackAuthenticatesPipelinedRequests(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "ordered"
		if reverse {
			name = "reversed"
		}
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			c := newCallback(t.Context(), "fixture", "192.0.2.210", slog.New(slog.NewJSONHandler(&logs, nil)))
			if err := c.configureCredentials("fixture-user", "synthetic-password"); err != nil {
				t.Fatal(err)
			}
			calls := make(chan struct{}, 2)
			c.passthrough = func(json.RawMessage) json.RawMessage {
				calls <- struct{}{}
				return json.RawMessage(`{"error_code":0}`)
			}
			client, recorder := net.Pipe()
			attempt := &callbackAttempt{events: make(chan omadalink.Event, 2)}
			c.active = attempt
			done := make(chan string, 1)
			go func() { done <- c.applicationSession(t.Context(), client, attempt) }()
			stop := sync.OnceFunc(func() { _ = recorder.Close(); _ = client.Close(); <-done })
			t.Cleanup(stop)
			_ = recorder.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(recorder)
			read := func() map[string]json.RawMessage {
				t.Helper()
				frame, err := omadalink.ReadApplicationFrame(reader)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]json.RawMessage
				if err := json.Unmarshal(frame.Body, &body); err != nil {
					t.Fatal(err)
				}
				return body
			}
			write := func(kind, body string) {
				t.Helper()
				wire := strings.Replace(diagnosticFrame(body), "Content-Type:Request", "Content-Type:"+kind, 1)
				if _, err := io.WriteString(recorder, wire); err != nil {
					t.Fatal(err)
				}
			}
			read() // Camera declaration.
			var challenges [2]map[string]string
			for i := range challenges {
				request, _ := json.Marshal(map[string]any{"id": i + 1, "method": "passthrough", "requestData": map[string]any{"method": "get", "system": map[string]string{"name": "time_status"}}})
				write("Request", string(request))
				response := read()
				if string(response["error_code"]) != "-40401" {
					t.Fatal("unauthenticated request was not challenged")
				}
				var challenge struct{ Nonce, NC string }
				if err := json.Unmarshal(response["responseData"], &challenge); err != nil {
					t.Fatal(err)
				}
				challenges[i] = map[string]string{"nonce": challenge.Nonce, "nc": challenge.NC}
			}
			if len(calls) != 0 || c.snapshot().ApplicationAuthenticated {
				t.Fatal("pipelined requests bypassed authentication")
			}
			// Independent recorder formula and synthetic HA1 from the account vectors.
			hash := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
			for i := range challenges {
				index := i
				if reverse {
					index = len(challenges) - 1 - i
				}
				challenge := challenges[index]
				nonce, count := challenge["nonce"], challenge["nc"]
				proof := hash("d0b9e2378c49cee5509784ee7d6e86ef:" + nonce + ":" + count + ":" + nonce + ":auth:" + hash("digestmd5:tplink"))
				request, _ := json.Marshal(map[string]any{"id": i + 3, "method": "auth", "requestData": map[string]string{"username": "fixture-user", "realm": "vigi", "nonce": nonce, "nc": count, "uri": "tplink", "qop": "auth", "cnonce": "synthetic-client-nonce", "response": proof}})
				write("Auth", string(request))
				response := read()
				if string(response["error_code"]) != "0" {
					t.Fatalf("valid answer %d to a pending challenge was rejected", i+1)
				}
			}
			write("Request", `{"id":5,"method":"passthrough","requestData":{"method":"get","system":{"name":"time_status"}}}`)
			if string(read()["error_code"]) != "0" || len(calls) != 1 || !c.snapshot().ApplicationAuthenticated {
				t.Fatal("pipelined authentication did not retain authorized passthrough")
			}
			stop()
			for _, private := range []string{"fixture-user", "synthetic-password", "synthetic-client-nonce", challenges[0]["nonce"], challenges[1]["nonce"]} {
				if strings.Contains(logs.String(), private) {
					t.Fatal("callback diagnostics exposed account material")
				}
			}
		})
	}
}
