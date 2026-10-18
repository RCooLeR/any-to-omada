package omadalink

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandshakeDiagnosticsAfterVersionExchange(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var incoming, outgoing bytes.Buffer
	if err := writeSyntheticServerFrame(&incoming, AlgorithmVersion, 1, []byte("1.0")); err != nil {
		t.Fatal(err)
	}
	if err := writeHandshakeMessage(&outgoing, AlgorithmVersion, 2, []byte("1.0")); err != nil {
		t.Fatal(err)
	}
	incomingBytes, outgoingBytes := int64(incoming.Len()), int64(outgoing.Len())
	peerDone := make(chan error, 1)
	go func() {
		if _, err := io.Copy(server, &incoming); err != nil {
			peerDone <- err
			return
		}
		_, err := ReadFrame(bufio.NewReader(server), false)
		peerDone <- err
	}()
	tracked := &secondReadConn{Conn: client, secondRead: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := Handshake(ctx, tracked, "synthetic-private-registration")
		done <- err
	}()
	select {
	case <-tracked.secondRead:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("handshake never waited for the recorder parameters")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrHandshake) {
			t.Fatal("canceled parameter read lost its error identity")
		}
		assertHandshakeDiagnostics(t, fmt.Errorf("outer operation: %w", err), "read_parameters", incomingBytes, outgoingBytes)
		if strings.Contains(err.Error(), "private") {
			t.Fatal("diagnostic error exposed the registration value")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled parameter read did not stop")
	}
	if err := <-peerDone; err != nil {
		t.Fatal("synthetic recorder did not receive the version reply")
	}
}

func TestHandshakeDiagnosticsRejectPrivatePayloadWithoutLoggingIt(t *testing.T) {
	const payload = `{"step":1,"error_code":0,"data":"private-payload"}`
	encoded, err := Encode(Frame{ContentType: AlgorithmVersion, Body: []byte(payload)}, true)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	peerDone := make(chan error, 1)
	go func() {
		_, err := server.Write(encoded)
		peerDone <- err
	}()
	_, err = Handshake(context.Background(), client, "private-registration")
	if !errors.Is(err, ErrHandshake) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "data") {
		t.Fatal("handshake diagnostic exposed input data")
	}
	assertHandshakeDiagnostics(t, err, "read_version", int64(len(encoded)), 0)
	if err := <-peerDone; err != nil {
		t.Fatal("synthetic invalid frame was not delivered")
	}
	for _, unrelated := range []error{nil, errors.New("private-unrelated"), ErrHandshake} {
		if _, ok := FailureDiagnostics(unrelated); ok {
			t.Fatal("unrelated error acquired handshake progress")
		}
	}
}

func assertHandshakeDiagnostics(t *testing.T, err error, stage string, received, sent int64) {
	t.Helper()
	diagnostics, ok := FailureDiagnostics(err)
	if !ok || diagnostics.Stage != stage || diagnostics.ReceivedBytes != received || diagnostics.SentBytes != sent {
		t.Fatalf("handshake progress mismatch: stage=%s received=%d sent=%d present=%v", diagnostics.Stage, diagnostics.ReceivedBytes, diagnostics.SentBytes, ok)
	}
}

type secondReadConn struct {
	net.Conn
	reads      atomic.Int32
	secondRead chan struct{}
}

func (c *secondReadConn) Read(data []byte) (int, error) {
	if c.reads.Add(1) == 2 {
		close(c.secondRead)
	}
	return c.Conn.Read(data)
}
