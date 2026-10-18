package camerartsp

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
)

func TestClientCountsTrackDownstreamSessionsAndDistinctIPs(t *testing.T) {
	f := newFixture(t)
	s := startProxy(t, f.config())
	await(t, func() bool {
		status := s.Status()
		return status.Profiles["stream1"].State == "ready" && status.Profiles["stream2"].State == "ready"
	})
	assertClientCounts(t, s, 0, 0)

	main, _, _ := reader(t, s, "/stream1")
	sub, _, _ := reader(t, s, "/stream2")
	awaitClientCounts(t, s, 2, 1)
	encoded, err := json.Marshal(s.Status())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("127.0.0.1")) || bytes.Contains(encoded, []byte("rtsp://")) {
		t.Fatal("status exposed a client or source endpoint")
	}

	main.Close()
	awaitClientCounts(t, s, 1, 1)
	sub.Close()
	awaitClientCounts(t, s, 0, 0)
	if status := s.Status(); status.Profiles["stream1"].State != "ready" || status.Profiles["stream2"].State != "ready" {
		t.Fatal("closing downstream sessions stopped the shared source profiles")
	}
}

func TestClientCountsExcludeSetupUntilPlay(t *testing.T) {
	f := newFixture(t)
	s := startProxy(t, f.config())
	await(t, func() bool { return s.Status().Profiles["stream1"].State == "ready" })
	u, err := base.ParseURL("rtsp://" + s.Addr() + "/stream1")
	if err != nil {
		t.Fatal(err)
	}
	tcp := gortsplib.ProtocolTCP
	client := &gortsplib.Client{Scheme: u.Scheme, Host: u.Host, Protocol: &tcp}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	desc, _, err := client.Describe(u)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetupAll(desc.BaseURL, desc.Medias); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return s.Status().Sessions == 1 })
	assertClientCounts(t, s, 0, 0)
	if _, err := client.Play(nil); err != nil {
		t.Fatal(err)
	}
	awaitClientCounts(t, s, 1, 1)
	client.Close()
	awaitClientCounts(t, s, 0, 0)
}

func assertClientCounts(t *testing.T, s *Server, wantStreams, wantIPs int) {
	t.Helper()
	streams, ips := s.ClientCounts()
	if streams != wantStreams || ips != wantIPs {
		t.Fatalf("counts = %d/%d, want %d/%d", streams, ips, wantStreams, wantIPs)
	}
}

func awaitClientCounts(t *testing.T, s *Server, wantStreams, wantIPs int) {
	t.Helper()
	await(t, func() bool {
		streams, ips := s.ClientCounts()
		return streams == wantStreams && ips == wantIPs
	})
}
