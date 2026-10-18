package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func TestCallbackPassthroughResponseAndHeartbeatContinuity(t *testing.T) {
	var logs bytes.Buffer
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewJSONHandler(&logs, nil)))
	calls := 0
	c.passthrough = func(raw json.RawMessage) json.RawMessage {
		calls++
		if string(raw) != `{"method":"get","system":{"name":"private camera+name"}}` {
			t.Error("dispatcher did not receive the decoded object")
		}
		return json.RawMessage(`{"error_code":-40106,"result":{"name":"private reply"}}`)
	}
	ctx, cancel := context.WithCancel(t.Context())
	client, peer := net.Pipe()
	messages := make(chan callbackMessage, 4)
	failures := make(chan callbackReadFailure, 1)
	done := make(chan struct{})
	go func() { defer close(done); c.readCallback(ctx, client, messages, failures) }()
	t.Cleanup(func() { cancel(); _ = client.Close(); _ = peer.Close(); <-done })
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	command := `{"id":2,"method":"passthrough","requestData":{"method":"get","system":{"name":"private%20camera+name"}}}`
	if _, err := io.WriteString(peer, diagnosticFrame(command)); err != nil {
		t.Fatal(err)
	}
	message := <-messages
	writeDone := make(chan string, 1)
	go func() { writeDone <- c.writePassthrough(client, message) }()
	frame, err := omadalink.ReadApplicationFrame(bufio.NewReader(peer))
	if err != nil {
		t.Fatal(err)
	}
	if failure := <-writeDone; failure != "" {
		t.Fatalf("passthrough response failed: %s", failure)
	}
	var reply struct {
		ID           int `json:"id"`
		ErrorCode    int `json:"error_code"`
		ResponseData struct {
			ErrorCode int `json:"error_code"`
		} `json:"responseData"`
	}
	if json.Unmarshal(frame.Body, &reply) != nil || frame.ContentType != omadalink.ApplicationResponse || reply.ID != 2 || reply.ErrorCode != 0 || reply.ResponseData.ErrorCode != -40106 || calls != 1 {
		t.Fatal("management rejection was not correlated and nested correctly")
	}
	if _, err := io.WriteString(peer, diagnosticFrame(`{"id":3,"method":"heartbeat"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case heartbeat := <-messages:
		if heartbeat.Method != "heartbeat" {
			t.Fatal("passthrough consumed the following heartbeat")
		}
	case <-time.After(time.Second):
		t.Fatal("callback stopped after passthrough")
	}
	cancel()
	_ = client.Close()
	<-done
	if strings.Contains(logs.String(), "private") || strings.Contains(logs.String(), "%20") {
		t.Fatal("passthrough request or response leaked into logs")
	}
}

func TestCallbackMethodSpecificDataValidation(t *testing.T) {
	declaration, err := decodeCallbackMessage(json.RawMessage(`{"id":1,"method":"declaration","requestData":{"version":"0101000101"}}`))
	if err != nil || declaration.peerVersion != "0101000101" || !validPeerVersion(declaration.peerVersion) {
		t.Fatalf("valid declaration changed: %v", err)
	}
	for _, body := range []string{
		`{"id":1,"method":"declaration","requestData":{"version":1}}`,
		`{"id":1,"method":"declaration","requestData":"0101000101"}`,
		`{"id":1,"method":"passthrough","requestData":"%7b%7d"}`,
		`{"id":1,"method":"passthrough","requestData":[]}`,
		`{"id":1,"method":"passthrough","requestData":null}`,
		`{"id":1,"method":"passthrough"}`,
	} {
		if _, err := decodeCallbackMessage(json.RawMessage(body)); err == nil {
			t.Fatal("invalid method data accepted")
		}
	}
	command, err := decodeCallbackMessage(json.RawMessage(`{"id":1,"method":"passthrough","requestData":{"version":{"name":"unrelated management selector"},"method":"get"}}`))
	if err != nil || command.Method != "passthrough" {
		t.Fatalf("management selector decoded as declaration metadata: %v", err)
	}
	response, err := decodeCallbackMessage(json.RawMessage(`{"id":32768,"method":"response","responseData":{"error_code":-40106}}`))
	if err != nil || response.responseCode != -40106 {
		t.Fatalf("existing response handling changed: %v", err)
	}
}

func TestCallbackMalformedPassthroughNeverInvokesDispatcher(t *testing.T) {
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	called := false
	c.passthrough = func(json.RawMessage) json.RawMessage {
		called = true
		return json.RawMessage(`{"error_code":0}`)
	}
	failure := c.writePassthrough(nil, callbackMessage{ID: 1, Method: "passthrough", RequestData: json.RawMessage(`{"method":"get","value":"%gg"}`)})
	if failure != "passthrough_request" || called {
		t.Fatal("malformed percent coding reached virtual management")
	}
}
