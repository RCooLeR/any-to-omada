package camerartsp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/gortsplib/v5/pkg/liberrors"
	"github.com/pion/rtp"
)

type fixture struct {
	server    *gortsplib.Server
	streams   map[string]*gortsplib.ServerStream
	mu        sync.Mutex
	conns     map[*gortsplib.ServerConn]bool
	describes map[string]int
	requests  atomic.Int64
	status    atomic.Int64
	stall     atomic.Bool
	done      chan struct{}
	wg        sync.WaitGroup
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{streams: map[string]*gortsplib.ServerStream{}, conns: map[*gortsplib.ServerConn]bool{}, describes: map[string]int{}, done: make(chan struct{})}
	f.server = &gortsplib.Server{RTSPAddress: "127.0.0.1:0", Handler: f}
	if err := f.server.Start(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/main", "/sub"} {
		var video format.Format = &format.H264{PayloadTyp: 96, PacketizationMode: 1, SPS: []byte{0x67, 0x42, 0x00, 0x1e, 0x88, 0x8b, 0x60}, PPS: []byte{0x68, 0xce, 0x38, 0x80}}
		if path == "/sub" {
			video = &format.H265{PayloadTyp: 96}
		}
		stream := &gortsplib.ServerStream{Server: f.server, Desc: &description.Session{Title: "private-upstream-title", Medias: []*description.Media{
			{Type: description.MediaTypeVideo, Formats: []format.Format{video}},
			{Type: description.MediaTypeAudio, Formats: []format.Format{&format.G711{PayloadTyp: 0, SampleRate: 8000, ChannelCount: 1, MULaw: true}}},
		}}}
		if err := stream.Initialize(); err != nil {
			t.Fatal(err)
		}
		f.streams[path] = stream
	}
	// A single producer sends distinct video payloads for the two profiles.
	f.wg.Go(func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var number uint16
		for {
			select {
			case <-f.done:
				return
			case <-ticker.C:
			}
			if f.stall.Load() {
				continue
			}
			number++
			for path, stream := range f.streams {
				payload := []byte{0x65, 1, 2, 3}
				if path == "/sub" {
					payload = []byte{0x26, 1, 4, 5}
				}
				_ = stream.WritePacketRTP(stream.Desc.Medias[0], &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: number, Timestamp: uint32(number) * 900, SSRC: 1, Marker: true}, Payload: payload})
				_ = stream.WritePacketRTP(stream.Desc.Medias[1], &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: number, Timestamp: uint32(number) * 80, SSRC: 2}, Payload: []byte{9, 8, 7}})
			}
		}
	})
	t.Cleanup(func() {
		close(f.done)
		f.wg.Wait()
		for _, stream := range f.streams {
			stream.Close()
		}
		f.server.Close()
	})
	return f
}

func (f *fixture) OnConnOpen(ctx *gortsplib.ServerHandlerOnConnOpenCtx) {
	f.mu.Lock()
	f.conns[ctx.Conn] = true
	f.mu.Unlock()
}
func (f *fixture) OnConnClose(ctx *gortsplib.ServerHandlerOnConnCloseCtx) {
	f.mu.Lock()
	delete(f.conns, ctx.Conn)
	f.mu.Unlock()
}
func (f *fixture) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx) (*base.Response, *gortsplib.ServerStream, error) {
	f.requests.Add(1)
	if code := f.status.Load(); code != 0 {
		return &base.Response{StatusCode: base.StatusCode(code)}, nil, nil
	}
	if !ctx.Conn.VerifyCredentials(ctx.Request, "fixture-user", "private-fixture-password") {
		return &base.Response{StatusCode: base.StatusUnauthorized}, nil, liberrors.ErrServerAuth{}
	}
	f.mu.Lock()
	f.describes[ctx.Path]++
	f.mu.Unlock()
	stream := f.streams[ctx.Path]
	if stream == nil {
		return &base.Response{StatusCode: base.StatusNotFound}, nil, nil
	}
	return &base.Response{StatusCode: base.StatusOK}, stream, nil
}
func (f *fixture) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	return &base.Response{StatusCode: base.StatusOK}, f.streams[ctx.Path], nil
}
func (f *fixture) OnPlay(*gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	return &base.Response{StatusCode: base.StatusOK}, nil
}

func (f *fixture) config() Config {
	host, port, _ := net.SplitHostPort(f.server.NetListener().Addr().String())
	number, _ := strconv.Atoi(port)
	return Config{Address: "127.0.0.1:0", AllowedClientIPs: []string{"127.0.0.1"}, UpstreamIP: host, UpstreamPort: number,
		MainURL: "rtsp://" + net.JoinHostPort(host, port) + "/main", SubURL: "rtsp://" + net.JoinHostPort(host, port) + "/sub", Username: "fixture-user", Password: "private-fixture-password",
		ConnectTimeout: time.Second, ReadTimeout: 2 * time.Second, RetryMin: 50 * time.Millisecond, RetryMax: 100 * time.Millisecond}
}

func startProxy(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func await(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type receivedPacket struct {
	kind    description.MediaType
	payload []byte
}

func reader(t *testing.T, s *Server, path string) (*gortsplib.Client, *description.Session, <-chan receivedPacket) {
	t.Helper()
	u, _ := base.ParseURL("rtsp://" + s.Addr() + path)
	tcp := gortsplib.ProtocolTCP
	client := &gortsplib.Client{Scheme: u.Scheme, Host: u.Host, Protocol: &tcp, ReadTimeout: time.Second}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	desc, _, err := client.Describe(u)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetupAll(desc.BaseURL, desc.Medias); err != nil {
		t.Fatal(err)
	}
	packets := make(chan receivedPacket, 128)
	client.OnPacketRTPAny(func(media *description.Media, _ format.Format, packet *rtp.Packet) {
		select {
		case packets <- receivedPacket{media.Type, bytes.Clone(packet.Payload)}:
		default:
		}
	})
	if _, err = client.Play(nil); err != nil {
		t.Fatal(err)
	}
	return client, desc, packets
}

func TestSharesProfilesPreservesVideoAndAudio(t *testing.T) {
	f := newFixture(t)
	s := startProxy(t, f.config())
	await(t, func() bool {
		v := s.Status()
		return v.Profiles["stream1"].State == "ready" && v.Profiles["stream2"].State == "ready"
	})
	for i, path := range []string{"/stream1", "/stream1", "/stream2"} {
		_, desc, packets := reader(t, s, path)
		if desc.Title != "Camera proxy" || len(desc.Medias) != 2 {
			t.Fatalf("unexpected description: title=%q tracks=%d", desc.Title, len(desc.Medias))
		}
		if i < 2 {
			if _, ok := desc.Medias[0].Formats[0].(*format.H264); !ok {
				t.Fatal("H264 was not preserved")
			}
		} else {
			if _, ok := desc.Medias[0].Formats[0].(*format.H265); !ok {
				t.Fatal("H265 was not preserved")
			}
		}
		seen := map[description.MediaType]bool{}
		for len(seen) < 2 {
			select {
			case packet := <-packets:
				want := []byte{9, 8, 7}
				if packet.kind == description.MediaTypeVideo {
					want = []byte{0x65, 1, 2, 3}
					if i == 2 {
						want = []byte{0x26, 1, 4, 5}
					}
				}
				if !bytes.Equal(packet.payload, want) {
					t.Fatal("payload changed")
				}
				seen[packet.kind] = true
			case <-time.After(2 * time.Second):
				t.Fatal("media delivery timed out")
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.describes["/main"] != 1 || f.describes["/sub"] != 1 {
		t.Fatalf("upstream should be shared: %v", f.describes)
	}
	encoded, _ := json.Marshal(s.Status())
	for _, private := range []string{"fixture-user", "private-fixture-password", "/main", "private-upstream-title"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("status disclosed private source data")
		}
	}
}

func TestAuthenticationLatchesWithoutRetries(t *testing.T) {
	f := newFixture(t)
	f.status.Store(int64(base.StatusForbidden))
	s := startProxy(t, f.config())
	await(t, func() bool {
		return s.Status().AuthFailed && s.Status().Profiles["stream1"].State == "authentication_failed" && s.Status().Profiles["stream2"].State == "authentication_failed"
	})
	before := f.requests.Load()
	time.Sleep(250 * time.Millisecond)
	if f.requests.Load() != before {
		t.Fatal("authentication rejection was retried")
	}
	if !s.Status().Listening {
		t.Fatal("status listener should remain available after auth rejection")
	}
}

func TestRejectedPasswordLatchesAfterChallenge(t *testing.T) {
	f := newFixture(t)
	cfg := f.config()
	cfg.Password = "incorrect-fixture-password"
	s := startProxy(t, cfg)
	await(t, func() bool { return s.Status().AuthFailed })
	await(t, func() bool {
		return s.Status().Profiles["stream1"].State == "authentication_failed" && s.Status().Profiles["stream2"].State == "authentication_failed"
	})
	before := f.requests.Load()
	time.Sleep(150 * time.Millisecond)
	if f.requests.Load() != before {
		t.Fatal("rejected credentials were retried")
	}
}

func TestMissingProfileDoesNotRetry(t *testing.T) {
	f := newFixture(t)
	f.status.Store(int64(base.StatusNotFound))
	s := startProxy(t, f.config())
	await(t, func() bool {
		return s.Status().Profiles["stream1"].State == "configuration_error" && s.Status().Profiles["stream2"].State == "configuration_error"
	})
	before := f.requests.Load()
	time.Sleep(150 * time.Millisecond)
	if f.requests.Load() != before || s.Status().AuthFailed {
		t.Fatal("missing profile should stop without being labeled authentication failure")
	}
}

func TestTransientDisconnectReopensProfiles(t *testing.T) {
	f := newFixture(t)
	s := startProxy(t, f.config())
	await(t, func() bool {
		return s.Status().Profiles["stream1"].State == "ready" && s.Status().Profiles["stream2"].State == "ready"
	})
	f.mu.Lock()
	connections := make([]*gortsplib.ServerConn, 0, len(f.conns))
	for conn := range f.conns {
		connections = append(connections, conn)
	}
	f.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	await(t, func() bool {
		status := s.Status()
		return status.Profiles["stream1"].Attempts >= 2 && status.Profiles["stream2"].Attempts >= 2 && status.Profiles["stream1"].State == "ready" && status.Profiles["stream2"].State == "ready"
	})
}

func TestCancellationAndConcurrentClose(t *testing.T) {
	f := newFixture(t)
	f.stall.Store(true)
	s, err := New(f.config(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return f.requests.Load() >= 2 })
	cancel()
	var group sync.WaitGroup
	for range 8 {
		group.Go(s.Close)
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel pending startup")
	}
	if s.Status().Listening {
		t.Fatal("listener survived Close")
	}
}

func TestConfigurationAndDescriptionOrigin(t *testing.T) {
	f := newFixture(t)
	valid := f.config()
	for _, change := range []func(*Config){
		func(c *Config) { c.MainURL = "rtsp://127.0.0.2/main" },
		func(c *Config) { c.MainURL = strings.Replace(c.MainURL, "rtsp://", "rtsp://secret@", 1) },
		func(c *Config) { c.Address = "localhost:554" },
		func(c *Config) { c.SubURL = c.MainURL },
	} {
		cfg := valid
		change(&cfg)
		if _, err := New(cfg, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	s, err := New(valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseURL, _ := base.ParseURL(valid.MainURL)
	desc := &description.Session{BaseURL: baseURL, Medias: []*description.Media{{Type: description.MediaTypeVideo, Control: "rtsp://127.0.0.2/foreign", Formats: []format.Format{&format.H264{PayloadTyp: 96}}}}}
	if s.validDescription(desc) {
		t.Fatal("foreign track control accepted")
	}
	desc.Medias[0].Control = "trackID=0"
	if !s.validDescription(desc) {
		t.Fatal("same-origin track refused")
	}
}

func TestClientLimitAndUnknownPaths(t *testing.T) {
	f := newFixture(t)
	cfg := f.config()
	cfg.AllowedClientIPs = nil
	cfg.MaxClients = 1
	s := startProxy(t, cfg)
	first, err := net.DialTimeout("tcp", s.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	await(t, func() bool { return s.Status().Clients == 1 })
	second, err := net.DialTimeout("tcp", s.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if _, err = second.Read(buffer[:]); err == nil {
		t.Fatal("excess connection was accepted")
	}
	if networkError, ok := errors.AsType[net.Error](err); ok && networkError.Timeout() {
		t.Fatal("excess connection stayed open until the read deadline")
	}
	if _, code := s.selected("/unknown", ""); code != base.StatusNotFound {
		t.Fatal("unknown path accepted")
	}
	if _, code := s.selected("/stream1", "secret=value"); code != base.StatusNotFound {
		t.Fatal("arbitrary output query accepted")
	}
}

func TestRTSPWithoutAllowlistStreamsToAnyPeer(t *testing.T) {
	f := newFixture(t)
	for _, peers := range [][]string{nil, {}} {
		cfg := f.config()
		cfg.AllowedClientIPs = peers
		s := startProxy(t, cfg)
		await(t, func() bool { return s.Status().Profiles["stream1"].State == "ready" })
		client, _, packets := reader(t, s, "/stream1")
		select {
		case <-packets:
		case <-time.After(2 * time.Second):
			t.Fatal("unrestricted RTSP client received no media")
		}
		client.Close()
		s.Close()
	}
}

func TestRTSPListenerWithoutAllowlistAcceptsUnlistedPeer(t *testing.T) {
	for _, allowed := range []map[netip.Addr]bool{nil, {}} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_ = listener.Close()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		limited := &limitedListener{Listener: &singleListener{Listener: listener, conn: &peerConn{Conn: server}}, allowed: allowed, limit: 1}
		conn, err := limited.Accept()
		if err != nil || limited.count.Load() != 1 {
			t.Fatal("RTSP listener rejected an unlisted peer without an allowlist")
		}
		_ = conn.Close()
		_ = conn.Close()
		if limited.count.Load() != 0 {
			t.Fatal("RTSP close did not release exactly one connection slot")
		}
	}
}

func TestListenerRejectsUnlistedPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := &limitedListener{Listener: listener, allowed: map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}, limit: 1}
	defer limited.Close()
	// A controlled connection wrapper supplies a non-loopback peer without
	// contacting any real network endpoint.
	server, client := net.Pipe()
	defer client.Close()
	fake := &singleListener{Listener: listener, conn: &peerConn{Conn: server}}
	limited.Listener = fake
	done := make(chan error, 1)
	go func() { _, err := limited.Accept(); done <- err }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := client.Read(data[:]); err != io.EOF {
		t.Fatalf("unlisted peer was not closed: %v", err)
	}
	limited.Close()
	<-done
}

type peerConn struct{ net.Conn }

func (*peerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 1234}
}

type singleListener struct {
	net.Listener
	conn net.Conn
}

func (l *singleListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		return conn, nil
	}
	return l.Listener.Accept()
}
