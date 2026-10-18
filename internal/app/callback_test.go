package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func TestCallbackHandshakeFailureLogsStageWithoutRegistrationSecret(t *testing.T) {
	var output bytes.Buffer
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	}
	attempt := &callbackAttempt{registration: omadafront.CallbackRequest{IP: "192.0.2.150", Port: 6000, AuthCode: "private-registration-proof"}}
	if got := c.session(t.Context(), attempt); got != "handshake" {
		t.Fatal("closed recorder connection was not reported as a handshake failure")
	}
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	// A closed net.Pipe fails when the handshake first sets its deadline.
	if fields["handshake_stage"] != "set_deadline" || fields["received_bytes"] != float64(0) || fields["sent_bytes"] != float64(0) || fields["timed_out"] != false {
		t.Fatal("callback log lost the failed handshake stage or byte counts")
	}
	for _, private := range []string{attempt.registration.AuthCode, attempt.registration.IP, "auth_code"} {
		if strings.Contains(output.String(), private) {
			t.Fatal("callback diagnostics exposed private registration data")
		}
	}
}

func TestCallbackLogsRecorderErrorWithoutFramePayload(t *testing.T) {
	frame, err := omadalink.Encode(omadalink.Frame{ContentType: omadalink.AlgorithmVersion, Body: []byte(`{"step":1,"error_code":-40106,"data":"private-frame-value"}`)}, true)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
	peerDone := make(chan error, 1)
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			_, err := peer.Write(frame)
			peerDone <- err
		}()
		return client, nil
	}
	attempt := &callbackAttempt{registration: omadafront.CallbackRequest{IP: "192.0.2.150", Port: 6000, AuthCode: "private-registration-proof"}}
	if c.session(t.Context(), attempt) != "handshake" {
		t.Fatal("recorder error did not stop authentication")
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["failure_reason"] != "remote_error" || fields["frame_prefix"] != "native" || fields["peer_step"] != float64(1) || fields["peer_error_code"] != float64(-40106) || fields["recorder_port"] != float64(6000) {
		t.Fatal("callback log omitted the recorder error metadata")
	}
	for _, private := range []string{attempt.registration.AuthCode, "private-frame-value", "auth_code"} {
		if strings.Contains(output.String(), private) {
			t.Fatal("callback log exposed private payload data")
		}
	}
}

func TestCallbackRegistrationReplacementAndShutdownJoinWorkers(t *testing.T) {
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(c.close)
	type attempt struct {
		address string
		stopped <-chan struct{}
	}
	started := make(chan attempt, 4)
	c.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		done := make(chan struct{})
		started <- attempt{address, done}
		<-ctx.Done()
		close(done)
		return nil, ctx.Err()
	}
	request := omadafront.CallbackRequest{IP: "192.0.2.150", Port: 6000, Version: "0101000101", AuthCode: "synthetic-one"}
	if err := c.register(request); err != nil {
		t.Fatal(err)
	}
	first := <-started
	if first.address != "192.0.2.150:6000" {
		t.Fatal("incorrect recorder endpoint")
	}
	if err := c.register(request); err != nil {
		t.Fatal(err)
	}
	if c.snapshot().Registrations != 1 {
		t.Fatal("duplicate registration created a second worker")
	}
	c.stop("192.0.2.151", 6000)
	select {
	case <-first.stopped:
		t.Fatal("unrelated stop closed registered recorder")
	default:
	}
	request.AuthCode = "synthetic-two"
	if err := c.register(request); err != nil {
		t.Fatal(err)
	}
	second := <-started
	select {
	case <-first.stopped:
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel earlier recorder session")
	}
	c.close()
	select {
	case <-second.stopped:
	default:
		t.Fatal("shutdown returned before worker stopped")
	}
	if c.register(request) == nil {
		t.Fatal("closed worker accepted registration")
	}
}

func TestNativeEventMappingPreservesClassesAndEdges(t *testing.T) {
	for _, test := range []struct {
		code, action, class, evidence string
		eventType                     omadalink.EventType
		status                        uint8
		ok                            bool
	}{
		{"VideoMotion", "Start", "unknown", "native_code", omadalink.EventMotion, 1, true},
		{"VideoMotion", "Stop", "unknown", "native_code", omadalink.EventMotion, 3, true},
		{"SmartMotionHuman", "Start", "human", "native_code", omadalink.EventHumanMotion, 1, true},
		{"SmartMotionVehicle", "Stop", "vehicle", "native_code", omadalink.EventVehicleMotion, 3, true},
		{"Intelligent", "Start", "unknown", "unclassified", 0, 0, false},
		{"Intelligent", "Start", "human", "operator_correlated", omadalink.EventHumanIntrusion, 1, true},
		{"Intelligent", "Start", "pet", "operator_correlated", omadalink.EventPetIntrusion, 1, true},
		{"VideoMotion", "Pulse", "unknown", "native_code", omadalink.EventMotion, 1, true},
	} {
		got, ok := nativeEvents(cameraevents.Event{Code: test.code, Action: test.action, Class: test.class, Evidence: test.evidence})
		if ok != test.ok || ok && (len(got) != 1 || got[0].Type != test.eventType || got[0].Status != test.status) {
			t.Fatalf("mapping mismatch for %s/%s/%s", test.code, test.action, test.class)
		}
	}
}

func TestCallbackQueueDoesNotReplayOfflineEvents(t *testing.T) {
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	event := cameraevents.Event{Code: "VideoMotion", Action: "Start"}
	if c.send(event) != "disconnected" {
		t.Fatal("unregistered event queued")
	}
	c.active = &callbackAttempt{events: make(chan omadalink.Event, 1), cancel: func() {}}
	c.status.State = "connected"
	if c.send(event) != "queued" || c.send(event) != "queue_full" {
		t.Fatal("bounded queue did not report backpressure")
	}
	if got := <-c.active.events; got.Type != omadalink.EventMotion || got.Status != 1 {
		t.Fatal("wrong event queued")
	}
	if c.snapshot().EventsWritten != 0 {
		t.Fatal("queued event claimed as written")
	}
	c.status.State = "reconnecting"
	if c.send(event) != "disconnected" || len(c.active.events) != 0 {
		t.Fatal("offline event retained for replay")
	}
	c.close()
}

func TestVirtualDeclarationIdentityIsStableAndDistinct(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := newCallback(t.Context(), "lens-one", "192.0.2.210", logger)
	b := newCallback(t.Context(), "lens-two", "192.0.2.211", logger)
	again := newCallback(t.Context(), "lens-one", "192.0.2.210", logger)
	if a.identity.MAC != again.identity.MAC || a.identity.MAC == b.identity.MAC || a.identity.MAC[0]&3 != 2 {
		t.Fatal("virtual MAC must be stable, distinct, locally administered and unicast")
	}
}

func TestCallbackSuppressesDisabledStartsButForwardsStops(t *testing.T) {
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.active = &callbackAttempt{events: make(chan omadalink.Event, 4), cancel: func() {}}
	c.status.State = "connected"
	c.allow = func(eventType omadalink.EventType) bool { return eventType == omadalink.EventHumanIntrusion }
	human := cameraevents.Event{Code: "Intelligent", Action: "Start", Class: "human", Evidence: "operator_correlated"}
	if c.send(cameraevents.Event{Code: "VideoMotion", Action: "Start"}) != "disabled_by_settings" {
		t.Fatal("disabled motion start was forwarded")
	}
	if c.send(cameraevents.Event{Code: "VideoMotion", Action: "Stop"}) != "queued" {
		t.Fatal("motion stop must pass like the real camera's stop-only reports")
	}
	if c.send(human) != "queued" {
		t.Fatal("enabled human intrusion start was suppressed")
	}
	if got := <-c.active.events; got.Type != omadalink.EventMotion || got.Status != 3 {
		t.Fatal("stop edge changed")
	}
	if got := <-c.active.events; got.Type != omadalink.EventHumanIntrusion || got.Status != 1 {
		t.Fatal("human intrusion start changed")
	}
	if c.snapshot().EventsSuppressed != 1 {
		t.Fatal("suppressed start was not counted")
	}
	c.close()
}

func TestCallbackMarkerStateFollowsClassifiedIntrusionEdges(t *testing.T) {
	c := newCallback(t.Context(), "test-camera", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.active = &callbackAttempt{events: make(chan omadalink.Event, 8), cancel: func() {}}
	c.status.State = "connected"
	human := cameraevents.Event{Code: "Intelligent", Action: "Start", Class: "human", Evidence: "operator_correlated"}
	if c.markerState().IntrusionActive {
		t.Fatal("marker alert active before any intrusion")
	}
	c.send(cameraevents.Event{Code: "VideoMotion", Action: "Start"})
	if c.markerState().IntrusionActive {
		t.Fatal("plain motion activated the intrusion alert")
	}
	c.send(human)
	if !c.markerState().IntrusionActive {
		t.Fatal("human intrusion start did not activate the alert")
	}
	human.Action = "Stop"
	c.send(human)
	if c.markerState().IntrusionActive {
		t.Fatal("human intrusion stop did not clear the alert")
	}
	c.intrusionSince.Store(time.Now().Add(-maxMarkerAlert - time.Second).UnixNano())
	if c.markerState().IntrusionActive {
		t.Fatal("stale alert without a stop edge stayed active")
	}
	c.allow = func(omadalink.EventType) bool { return false }
	human.Action = "Start"
	c.send(human)
	if c.markerState().IntrusionActive {
		t.Fatal("suppressed intrusion start activated the alert")
	}
	c.close()
}
