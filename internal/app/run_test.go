package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/config"
)

func TestPersistentDaemonReportsUnregisteredReadinessAndShutsDown(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ControlAddress = listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Storage.Directory = t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil))) }()
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	ready := false
	for !ready {
		select {
		case err := <-done:
			t.Fatalf("daemon exited during startup: %v", err)
		case <-deadline.C:
			t.Fatal("daemon did not become live")
		case <-retry.C:
			response, err := client.Get("http://" + cfg.ControlAddress + "/healthz")
			if err == nil {
				_ = response.Body.Close()
				ready = response.StatusCode == http.StatusOK
			}
		}
	}
	for _, path := range []string{"/status", "/readyz"} {
		response, err := client.Get("http://" + cfg.ControlAddress + path)
		if err != nil {
			t.Fatal(err)
		}
		var status map[string]any
		err = json.NewDecoder(response.Body).Decode(&status)
		_ = response.Body.Close()
		if err != nil || status["native_omada_ready"] != false || status["native_alarm_delivery"] != "implemented_unverified" || status["recorder_history_verified"] != false {
			t.Fatal("unregistered daemon overstated readiness or recorder verification")
		}
		if path == "/readyz" && response.StatusCode != http.StatusServiceUnavailable {
			t.Fatal("unregistered translator reported ready")
		}
		if len(status["sources"].([]any)) != len(cfg.Sources) || len(status["cameras"].([]any)) != len(cfg.Cameras) {
			t.Fatal("configured source/lens inventory missing")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon shutdown did not join workers")
	}
	if response, err := client.Get("http://" + cfg.ControlAddress + "/healthz"); err == nil {
		_ = response.Body.Close()
		t.Fatal("control listener survived shutdown")
	}
}

func TestManagementPeerBoundaryDoesNotImplicitlyTrustLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	restricted := restrict(listener, []string{"192.0.2.2"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := restricted.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := client.Read(buffer[:]); err != io.EOF {
		t.Fatalf("unlisted loopback peer not rejected before TLS: %v", err)
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener did not stop")
	}
}
