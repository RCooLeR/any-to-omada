package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func TestCallbackFakeRecorderAccountGateAndEventAcknowledgement(t *testing.T) {
	var output bytes.Buffer
	c := newCallback(t.Context(), "fixture", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
	if err := c.configureCredentials("fixture-user", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	c.passthrough = func(json.RawMessage) json.RawMessage {
		called <- struct{}{}
		return json.RawMessage(`{"error_code":0}`)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, recorder := net.Pipe()
	defer recorder.Close()
	_ = recorder.SetDeadline(time.Now().Add(5 * time.Second))
	attempt := &callbackAttempt{events: make(chan omadalink.Event, 2)}
	c.active = attempt
	done := make(chan string, 1)
	go func() { done <- c.applicationSession(ctx, client, attempt) }()
	t.Cleanup(func() { cancel(); _ = client.Close(); _ = recorder.Close() })
	reader := bufio.NewReader(recorder)
	read := func() omadalink.Frame {
		t.Helper()
		_ = recorder.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, err := omadalink.ReadApplicationFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	write := func(kind, body string) {
		t.Helper()
		_ = recorder.SetWriteDeadline(time.Now().Add(5 * time.Second))
		wire := "--start-boundary--\r\nContent-Type:" + kind + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n--end-boundary--\r\n"
		if _, err := recorder.Write([]byte(wire)); err != nil {
			t.Fatal(err)
		}
	}
	if read().ContentType != omadalink.ApplicationDeclaration {
		t.Fatal("missing declaration")
	}
	write("Request", `{"id":1,"method":"passthrough","requestData":{"method":"get","system":{"name":"time_status"}}}`)
	challenge := read()
	var reply struct {
		ErrorCode int `json:"error_code"`
		Data      struct {
			Nonce string `json:"nonce"`
			NC    string `json:"nc"`
		} `json:"responseData"`
	}
	if json.Unmarshal(challenge.Body, &reply) != nil || reply.ErrorCode != -40401 {
		t.Fatal("first request was not challenged")
	}
	select {
	case <-called:
		t.Fatal("unauthenticated passthrough dispatched")
	default:
	}
	// Independent recorder formula with a fixed synthetic HA1 vector. Both
	// nonce positions use the challenge nonce in this vendor callback protocol.
	hash := func(value string) string { h := md5.Sum([]byte(value)); return hex.EncodeToString(h[:]) }
	proof := hash("d0b9e2378c49cee5509784ee7d6e86ef:" + reply.Data.Nonce + ":" + reply.Data.NC + ":" + reply.Data.Nonce + ":auth:" + hash("digestmd5:tplink"))
	request, _ := json.Marshal(map[string]any{"id": 2, "method": "auth", "requestData": map[string]string{"username": "fixture-user", "realm": "vigi", "nonce": reply.Data.Nonce, "nc": reply.Data.NC, "uri": "tplink", "qop": "auth", "cnonce": "synthetic-client-nonce", "response": proof}})
	write("Auth", string(request))
	authReply := read()
	var auth struct {
		ErrorCode int `json:"error_code"`
		Data      struct {
			RespAuth string `json:"respauth"`
		} `json:"responseData"`
	}
	if json.Unmarshal(authReply.Body, &auth) != nil || auth.ErrorCode != 0 || auth.Data.RespAuth != "f1ff68751b078f36b029f071e23876a5" {
		t.Fatal("reciprocal authentication failed")
	}
	write("Request", `{"id":3,"method":"passthrough","requestData":{"method":"get","system":{"name":"time_status"}}}`)
	read()
	<-called
	attempt.events <- omadalink.Event{Type: omadalink.EventHumanIntrusion, Status: 1}
	event := read()
	var sent struct {
		ID uint16 `json:"id"`
	}
	if json.Unmarshal(event.Body, &sent) != nil || event.ContentType != omadalink.ApplicationEvent {
		t.Fatal("authenticated event missing")
	}
	write("Response", `{"id":`+strconv.Itoa(int(sent.ID))+`,"error_code":0,"responseData":{"notify_event":{"error_code":0}}}`)
	// A subsequent query/reply orders the application loop after the ACK.
	write("Request", `{"id":4,"method":"passthrough","requestData":{"method":"get","system":{"name":"time_status"}}}`)
	read()
	<-called
	status := c.snapshot()
	if !status.ApplicationAuthenticated || status.EventsAcknowledged != 1 || status.EventsPending != 0 {
		t.Fatal("native application authentication or ACK state missing")
	}
	readAlarm := func(want omadalink.Event) uint16 {
		t.Helper()
		frame := read()
		var alarm struct {
			ID          uint16 `json:"id"`
			Method      string `json:"method"`
			RequestData struct {
				Events []omadalink.Event `json:"notify_event"`
			} `json:"requestData"`
		}
		if json.Unmarshal(frame.Body, &alarm) != nil || frame.ContentType != omadalink.ApplicationEvent || alarm.Method != "notify" ||
			len(alarm.RequestData.Events) != 1 || alarm.RequestData.Events[0] != want {
			t.Fatalf("expected native event %+v, got %s", want, frame.Body)
		}
		return alarm.ID
	}
	ack := func(id uint16) {
		t.Helper()
		write("Response", `{"id":`+strconv.Itoa(int(id))+`,"error_code":0,"responseData":{"notify_event":{"error_code":0}}}`)
	}
	barrier := func(id uint16) {
		t.Helper()
		write("Request", `{"id":`+strconv.Itoa(int(id))+`,"method":"passthrough","requestData":{"method":"get","system":{"name":"time_status"}}}`)
		frame := read()
		var response struct {
			ID uint16 `json:"id"`
		}
		if frame.ContentType != omadalink.ApplicationResponse || json.Unmarshal(frame.Body, &response) != nil || response.ID != id {
			t.Fatal("application barrier did not return its management response")
		}
		<-called
	}
	// Exercise normalization, callback admission, the real application timer,
	// native framing and both ACKs without a camera or recorder connection.
	normalized, err := cameraevents.Normalize("fixture", time.Now(), `{"Code":"CrossLineDetection","Action":"Pulse","Index":0,"Data":{"RuleID":7,"Object":{"ObjectType":"Human"}}}`, nil)
	if err != nil || len(normalized) != 1 || c.send(normalized[0]) != "queued" {
		t.Fatal("normalized human line-crossing pulse was not queued")
	}
	ack(readAlarm(omadalink.Event{Type: omadalink.EventHumanLine, Status: 1}))
	ack(readAlarm(omadalink.Event{Type: omadalink.EventHumanLine, Status: 3}))
	barrier(5)
	status = c.snapshot()
	if status.EventsAcknowledged != 3 || status.EventsPending != 0 {
		t.Fatal("pulse start and timer-generated stop did not both complete the ACK flow")
	}
	// Fill the ACK window while the transport stays responsive. A queued stop
	// must survive backpressure until a recorder ACK frees one slot.
	pendingIDs := make([]uint16, 0, maxPendingEventAcks)
	for range maxPendingEventAcks {
		attempt.events <- omadalink.Event{Type: omadalink.EventMotion, Status: 1}
		pendingIDs = append(pendingIDs, readAlarm(omadalink.Event{Type: omadalink.EventMotion, Status: 1}))
	}
	attempt.events <- omadalink.Event{Type: omadalink.EventMotion, Status: 3}
	barrier(6)
	status = c.snapshot()
	if status.EventsPending != maxPendingEventAcks || status.EventsWritten != uint64(3+maxPendingEventAcks) || len(attempt.events) != 1 || status.EventsDropped != 0 {
		t.Fatal("full ACK window consumed or dropped the queued stop, or blocked management")
	}
	ack(pendingIDs[0])
	ack(readAlarm(omadalink.Event{Type: omadalink.EventMotion, Status: 3}))
	barrier(7)
	status = c.snapshot()
	if len(attempt.events) != 0 || status.EventsAcknowledged != 5 || status.EventsPending != maxPendingEventAcks-1 || status.EventsDropped != 0 {
		t.Fatal("recorder ACK did not release the retained stop without loss")
	}
	cancel()
	_ = recorder.Close()
	<-done
	for _, secret := range []string{"fixture-user", "synthetic-password", reply.Data.Nonce, proof, "respauth", "synthetic-client-nonce"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("callback account material leaked into diagnostics")
		}
	}
}
