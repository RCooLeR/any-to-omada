package dvripcapture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

type sinkRow struct {
	device, protocol, kind string
	data                   any
}

type memorySink struct {
	mu        sync.Mutex
	rows      []sinkRow
	heartbeat chan struct{}
}

func (s *memorySink) Write(device, protocol, kind string, data any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, sinkRow{device, protocol, kind, data})
	if kind == "heartbeat" && s.heartbeat != nil {
		select {
		case s.heartbeat <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *memorySink) snapshot() []sinkRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkRow(nil), s.rows...)
}

type fakePeer struct{ net.Conn }

func startFake(t *testing.T, serve func(fakePeer) error) (capture.Device, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			result <- err
			return
		}
		result <- serve(fakePeer{conn})
	}()
	return capture.Device{ID: "test-camera", Host: "127.0.0.1", NativePort: listener.Addr().(*net.TCPAddr).Port, Username: "viewer", Password: "example-only"}, result
}

func (p fakePeer) login(accepted bool) error {
	challenge, err := readFrame(p)
	if err != nil {
		return err
	}
	if challenge.header != challengeHeader() || len(challenge.body) != 0 {
		return errors.New("unexpected challenge request")
	}
	if err := writeFrame(p, [32]byte{}, []byte("Realm:Login to Test\r\nRandom:12345\r\n")); err != nil {
		return err
	}
	login, err := readFrame(p)
	if err != nil {
		return err
	}
	// Independently calculated from the legacy protocol with dummy credentials.
	const expected = "viewer&&6957FEA3A8700E3BC203F171865FA5B7EA9C358B14804726707E7B3E5C0BE75F"
	if string(login.body) != expected {
		return errors.New("unexpected login digest")
	}
	wanted := loginHeader()
	binary.LittleEndian.PutUint32(wanted[4:8], uint32(len(expected)))
	if wanted != login.header {
		return errors.New("unexpected login header")
	}
	var reply [32]byte
	if accepted {
		reply[9] = 8
		binary.LittleEndian.PutUint32(reply[16:20], 123)
	} else {
		reply[8] = 1
	}
	return writeFrame(p, reply, nil)
}

func (p fakePeer) request(method string) (map[string]any, error) {
	packet, err := readFrame(p)
	if err != nil {
		return nil, err
	}
	messages, err := jsonMessages(packet.body)
	if err != nil || len(messages) != 1 {
		return nil, errors.New("invalid test RPC")
	}
	message := messages[0]
	if message["method"] != method {
		return nil, fmt.Errorf("wanted %s, got %v", method, message["method"])
	}
	if packet.header[0] != 0xf6 || binary.LittleEndian.Uint32(packet.header[16:20]) != uint32(len(packet.body)) || binary.LittleEndian.Uint32(packet.header[24:28]) != 123 || message["session"] != json.Number("123") {
		return nil, errors.New("invalid authenticated RPC framing")
	}
	return message, nil
}

func (p fakePeer) reply(request map[string]any, params any, preceding string) error {
	body, err := json.Marshal(map[string]any{"id": request["id"], "result": true, "params": params})
	if err != nil {
		return err
	}
	var wire bytes.Buffer
	if err := writeFrame(&wire, [32]byte{0: 0xf6}, append([]byte(preceding), body...)); err != nil {
		return err
	}
	// Exercise fragmented headers and bodies rather than assuming recv == frame.
	for wire.Len() > 0 {
		if _, err := p.Write(wire.Next(min(7, wire.Len()))); err != nil {
			return err
		}
	}
	return nil
}

func (p fakePeer) setup(notification string) error {
	return p.setupMetadata(notification, false)
}

func (p fakePeer) setupMetadata(notification string, rejectMetadata bool) error {
	for _, call := range []struct{ method, configName string }{
		{"magicBox.getDeviceType", ""},
		{"magicBox.getSoftwareVersion", ""},
		{"configManager.getConfig", "Encode"},
		{"configManager.getConfig", "SmartMotionDetect"},
		{"eventManager.attach", ""},
	} {
		method := call.method
		request, err := p.request(method)
		if err != nil {
			return err
		}
		params := request["params"]
		switch method {
		case "configManager.getConfig":
			if !reflect.DeepEqual(params, map[string]any{"name": call.configName}) {
				return errors.New("unexpected configuration query")
			}
		case "eventManager.attach":
			if !reflect.DeepEqual(params, map[string]any{"codes": []any{"All"}}) {
				return errors.New("unexpected subscription")
			}
		}
		prefix := ""
		if call.configName == "SmartMotionDetect" {
			prefix = notification
		}
		if rejectMetadata && (method == "magicBox.getSoftwareVersion" || call.configName == "Encode") {
			body, err := json.Marshal(map[string]any{"id": request["id"], "result": false, "error": map[string]any{"code": 12345}})
			if err != nil {
				return err
			}
			if err := writeFrame(p, [32]byte{0: 0xf6}, body); err != nil {
				return err
			}
			continue
		}
		if err := p.reply(request, map[string]any{"table": []any{map[string]any{"Enable": true}}}, prefix); err != nil {
			return err
		}
	}
	return nil
}

func (p fakePeer) cleanup() error {
	for _, method := range []string{"eventManager.detach", "global.logout"} {
		request, err := p.request(method)
		if err != nil {
			return err
		}
		if method == "eventManager.detach" && !reflect.DeepEqual(request["params"], map[string]any{"codes": []any{"All"}}) {
			return errors.New("detach does not match attach")
		}
		if err := p.reply(request, nil, ""); err != nil {
			return err
		}
	}
	return nil
}

func awaitServer(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake server did not stop")
	}
}

func TestRunCapturesUnclassifiedNestedEventsAndKeepsSessionAlive(t *testing.T) {
	const notification = `{"method":"client.notifyEventStream","params":{"eventList":[{"Code":"Intelligent","Action":"Start","Index":0,"Data":{"UTC":1792069200,"event":{"ObjectID":9007199254740993,"unknown":[1,2]},"outputData":{"category":"unclassified","opaque":{"nested":true}}}}]}}` + "\n"
	keepalive := make(chan struct{}, 1)
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		if err := p.setup(notification); err != nil {
			return err
		}
		request, err := p.request("global.keepAlive")
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(request["params"], map[string]any{"timeout": json.Number("30"), "active": true}) {
			return errors.New("invalid keepalive parameters")
		}
		if err := p.reply(request, nil, ""); err != nil {
			return err
		}
		return p.cleanup()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &memorySink{heartbeat: keepalive}
	finished := make(chan error, 1)
	go func() { finished <- run(ctx, device, sink, timings{time.Second, 50 * time.Millisecond, time.Second}) }()
	select {
	case <-keepalive:
	case err := <-finished:
		t.Fatalf("capture ended before keepalive: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("missing keepalive")
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	awaitServer(t, server)
	wanted, err := jsonMessages([]byte(notification))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, row := range sink.snapshot() {
		if row.device != device.ID || row.protocol != "dvrip" {
			t.Fatalf("unexpected capture routing: %+v", row)
		}
		counts[row.kind]++
		if row.kind == "event" && !reflect.DeepEqual(row.data, wanted[0]) {
			t.Fatalf("native event was changed: %#v", row.data)
		}
		if row.kind == "heartbeat" || row.kind == "response" || row.kind == "identity" || row.kind == "configuration" {
			data := row.data.(map[string]any)
			if duration, ok := data["request_duration_ms"].(int64); !ok || duration < 0 {
				t.Fatalf("missing RPC request duration: %#v", row.data)
			}
			if row.kind == "heartbeat" && (data["method"] != "global.keepAlive" || data["response"].(map[string]any)["result"] != true) {
				t.Fatalf("incorrect heartbeat classification: %#v", row.data)
			}
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"identity": 2, "configuration": 2, "event": 1, "subscription": 1, "heartbeat": 1, "response": 3}) {
		t.Fatalf("unexpected records: %v", counts)
	}
}

func TestUnsupportedMetadataDoesNotPreventEventSubscription(t *testing.T) {
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		if err := p.setupMetadata("", true); err != nil {
			return err
		}
		request, err := p.request("global.keepAlive")
		if err != nil {
			return err
		}
		if err := p.reply(request, nil, ""); err != nil {
			return err
		}
		return p.cleanup()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sink := &memorySink{heartbeat: make(chan struct{}, 1)}
	finished := make(chan error, 1)
	go func() { finished <- run(ctx, device, sink, timings{time.Second, 10 * time.Millisecond, time.Second}) }()
	select {
	case <-sink.heartbeat:
	case err := <-finished:
		t.Fatalf("unsupported metadata stopped event capture: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not reach keepalive")
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	awaitServer(t, server)
	var rejected, subscribed int
	for _, row := range sink.snapshot() {
		if row.kind == "subscription" {
			subscribed++
		}
		data, _ := row.data.(map[string]any)
		response, _ := data["response"].(map[string]any)
		if response["result"] == false {
			rejected++
			if row.kind == "configuration" && data["configuration_name"] != "Encode" {
				t.Fatal("configuration response lost its request identity")
			}
		}
	}
	if rejected != 2 || subscribed != 1 {
		t.Fatal("metadata rejections or successful subscription were lost")
	}
}

func TestRejectedKeepalivePreservesCompleteResponseAndStillCleansUp(t *testing.T) {
	var expected map[string]any
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		if err := p.setup(""); err != nil {
			return err
		}
		request, err := p.request("global.keepAlive")
		if err != nil {
			return err
		}
		expected = map[string]any{
			"id": request["id"], "result": false,
			"error":  map[string]any{"code": json.Number("287637504"), "message": "fixture rejection", "details": map[string]any{"unknown": true}},
			"params": map[string]any{"UTC": json.Number("1792069200"), "outputData": []any{json.Number("9007199254740993")}},
		}
		body, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		if err := writeFrame(p, [32]byte{0: 0xf6}, body); err != nil {
			return err
		}
		return p.cleanup()
	})
	sink := &memorySink{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := run(ctx, device, sink, timings{time.Second, 20 * time.Millisecond, time.Second})
	if err == nil || !strings.Contains(err.Error(), "keepalive rejected") || errors.Is(err, capture.ErrAuthentication) {
		t.Fatalf("unexpected rejection semantics: %v", err)
	}
	awaitServer(t, server)
	var rejected, cleanup int
	for _, row := range sink.snapshot() {
		if row.kind == "heartbeat" {
			t.Fatal("rejected keepalive was counted as healthy")
		}
		if row.kind != "response" {
			continue
		}
		data := row.data.(map[string]any)
		switch data["method"] {
		case "global.keepAlive":
			rejected++
			if !reflect.DeepEqual(data["response"], expected) {
				t.Fatalf("native rejection envelope changed: %#v", data)
			}
			if duration, ok := data["request_duration_ms"].(int64); !ok || duration < 0 {
				t.Fatalf("rejection duration missing: %#v", data)
			}
		case "eventManager.detach", "global.logout":
			cleanup++
		}
	}
	if rejected != 1 || cleanup != 2 {
		t.Fatalf("rejection or cleanup telemetry lost: rejected=%d cleanup=%d", rejected, cleanup)
	}
}

func TestRejectedAuthenticationDoesNotRetryOrSendRPC(t *testing.T) {
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(false); err != nil {
			return err
		}
		var next [1]byte
		if _, err := p.Read(next[:]); !errors.Is(err, io.EOF) {
			return fmt.Errorf("expected connection close after rejected login, got %v", err)
		}
		return nil
	})
	sink := &memorySink{}
	if err := Run(context.Background(), device, sink); !errors.Is(err, capture.ErrAuthentication) {
		t.Fatalf("expected authentication sentinel, got %v", err)
	}
	if len(sink.snapshot()) != 0 {
		t.Fatal("authentication material was logged")
	}
	awaitServer(t, server)
}

var errSinkExhausted = errors.New("test sink exhausted")

type exhaustedSink struct{}

func (exhaustedSink) Write(string, string, string, any) error { return errSinkExhausted }

func TestSinkFailureStopsFurtherReadsAndLogsOut(t *testing.T) {
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		request, err := p.request("magicBox.getDeviceType")
		if err != nil {
			return err
		}
		if err := p.reply(request, map[string]any{"type": "test"}, ""); err != nil {
			return err
		}
		request, err = p.request("global.logout")
		if err != nil {
			return err
		}
		return p.reply(request, nil, "")
	})
	if err := Run(context.Background(), device, exhaustedSink{}); !errors.Is(err, errSinkExhausted) {
		t.Fatalf("expected sink error, got %v", err)
	}
	awaitServer(t, server)
}

func TestCancellationDuringPartialFrameStillAttemptsBoundedCleanup(t *testing.T) {
	partial := make(chan struct{})
	device, server := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		if err := p.setup(""); err != nil {
			return err
		}
		if _, err := p.Write([]byte{0xf6, 0, 0, 0, 100, 0, 0, 0}); err != nil {
			return err
		}
		close(partial)
		// Never complete the incoming frame or reply. Both cleanup requests must
		// still be attempted; the capture cannot wait forever for the reader.
		for _, method := range []string{"eventManager.detach", "global.logout"} {
			if _, err := p.request(method); err != nil {
				return err
			}
		}
		var next [1]byte
		_, err := p.Read(next[:])
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("capture did not close stalled connection: %w", err)
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, device, &memorySink{}, timings{time.Second, time.Minute, 300 * time.Millisecond})
	}()
	select {
	case <-partial:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not start partial frame")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup exceeded bounded window")
	}
	awaitServer(t, server)
}

func TestFramingLimitsAndIncompletePayload(t *testing.T) {
	var oversized [32]byte
	binary.LittleEndian.PutUint32(oversized[4:8], maxPayload+1)
	if _, err := readFrame(bytes.NewReader(oversized[:])); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized frame accepted: %v", err)
	}
	var truncated [32]byte
	binary.LittleEndian.PutUint32(truncated[4:8], 10)
	if _, err := readFrame(bytes.NewReader(append(truncated[:], 1))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated payload accepted: %v", err)
	}
	var output bytes.Buffer
	if err := writeFrame(&output, [32]byte{}, make([]byte, maxPayload+1)); err == nil || output.Len() != 0 {
		t.Fatal("oversized request was written")
	}
}

func TestMalformedDeviceDataDoesNotLeakIntoErrors(t *testing.T) {
	for _, payload := range []string{`{"password":"secret-marker", BROKEN}`, `null`, `[1]`} {
		_, err := jsonMessages([]byte(payload))
		if err == nil || strings.Contains(err.Error(), "secret-marker") {
			t.Fatalf("unsafe parse result: %v", err)
		}
	}
	if _, err := loginPayload("viewer", "unsupported-\u20ac", []byte("Realm:test\nRandom:1")); err == nil || strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsafe encoding error: %v", err)
	}
}
