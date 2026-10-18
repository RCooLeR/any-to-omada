package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func diagnosticFrame(body string) string {
	return fmt.Sprintf("--start-boundary--\r\nContent-Type:Request\r\nContent-Length:%d\r\n%s\r\n--end-boundary--", len(body), body)
}

func TestCallbackReaderIdentifiesStringCommandWithoutExposingContents(t *testing.T) {
	var output bytes.Buffer
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	messages := make(chan callbackMessage, 2)
	failures := make(chan callbackReadFailure, 1)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); c.readCallback(t.Context(), client, messages, failures) }()
	declaration := `{"id":1,"method":"declaration","requestData":{"version":"0101000101"}}`
	command := `{"id":2,"method":"passthrough","requestData":"%7B%22password%22%3A%22private-camera-password%22%7D"}`
	if _, err := io.WriteString(peer, diagnosticFrame(declaration)+diagnosticFrame(command)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("typed callback rejection blocked")
	}
	failure := <-failures
	if failure.stage != "message" || failure.frames != 2 || failure.lastFrame.method != "passthrough" || failure.lastFrame.requestKind != "string" {
		t.Fatalf("wrong read failure: stage=%s frames=%d", failure.stage, failure.frames)
	}
	if len(messages) != 1 || (<-messages).Method != "declaration" {
		t.Fatal("diagnostics changed existing message acceptance")
	}
	c.logCallbackReadFailure(failure, 2, 1)
	rows := diagnosticLogRows(t, output.Bytes())
	last := rows[len(rows)-1]
	if last["read_stage"] != "message" || last["failure_kind"] != "message_type" || last["message_field"] != "requestData" || last["last_message"] != "passthrough" {
		t.Fatalf("missing typed-message diagnostics: %v", last)
	}
	for _, secret := range []string{"private-camera-password", "%7B", "0101000101"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("callback diagnostics exposed a payload value")
		}
	}
}

func TestCallbackReaderBoundsMessageTraceAndReportsEOF(t *testing.T) {
	var output bytes.Buffer
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	count := callbackTraceFrameLimit + 9
	readReady := make(chan struct{})
	observed := &callbackDeadlineSignal{Conn: client, target: count + 1, ready: readReady}
	messages := make(chan callbackMessage, count)
	failures := make(chan callbackReadFailure, 1)
	done := make(chan struct{})
	go func() { defer close(done); c.readCallback(t.Context(), observed, messages, failures) }()
	for i := 0; i < count; i++ {
		if _, err := io.WriteString(peer, diagnosticFrame(`{"id":1,"method":"heartbeat"}`)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-readReady:
	case <-time.After(time.Second):
		t.Fatal("reader did not reach the next frame")
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback did not observe EOF")
	}
	failure := <-failures
	if len(messages) != count || failure.frames != uint64(count) {
		t.Fatal("trace cap dropped callback messages")
	}
	c.logCallbackReadFailure(failure, 3, 0)
	rows := diagnosticLogRows(t, output.Bytes())
	if len(rows) != callbackTraceFrameLimit+2 || rows[len(rows)-2]["msg"] != "native callback message trace limit reached" {
		t.Fatal("message trace was not bounded per connection")
	}
	last := rows[len(rows)-1]
	if last["failure_kind"] != "eof" || last["frame_stage"] != "prefix" || last["received_bytes"] != float64(0) || last["frames_received"] != float64(count) {
		t.Fatalf("EOF misreported: %v", last)
	}
}

func TestCallbackMetadataRestrictsPeerStringsAndNumericFields(t *testing.T) {
	body := []byte(`{"id":"secret-id","method":"private-secret-method","requestData":{"password":"private-proof","nonce":"private-nonce"},"error_code":"private-code","responseData":{"error_code":-40106,"token":"private-token"}}`)
	metadata := callbackMetadata(omadalink.Frame{ContentType: omadalink.ApplicationRequest, Body: body})
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Info("test", metadata.fields()...)
	if strings.Contains(output.String(), "private-") || metadata.method != "unknown" || metadata.idPresent || metadata.errorPresent || !metadata.responseSet || metadata.responseError != -40106 {
		t.Fatal("unsafe metadata or incorrect numeric-field handling")
	}
}

func TestCallbackReadFailureDistinguishesFramingAndTimeout(t *testing.T) {
	_, malformed := omadalink.ReadApplicationFrame(bufio.NewReader(strings.NewReader("--wrong-boundary---\r\n")))
	for _, test := range []struct {
		err  error
		kind string
	}{
		{malformed, "invalid_frame"},
		{io.ErrUnexpectedEOF, "truncated"},
		{context.DeadlineExceeded, "timeout"},
		{net.ErrClosed, "closed"},
	} {
		if callbackFailureKind(test.err) != test.kind {
			t.Errorf("failure kind: got %s, want %s", callbackFailureKind(test.err), test.kind)
		}
	}
}

func diagnosticLogRows(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var rows []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

type callbackDeadlineSignal struct {
	net.Conn
	target int
	calls  int
	ready  chan struct{}
}

func (c *callbackDeadlineSignal) SetReadDeadline(deadline time.Time) error {
	err := c.Conn.SetReadDeadline(deadline)
	c.calls++
	if c.calls == c.target {
		close(c.ready)
	}
	return err
}
