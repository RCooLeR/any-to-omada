package camerartsp

import (
	"bufio"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/auth"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/conn"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/pion/rtp"
)

func TestVirtualCredentialsMustBePaired(t *testing.T) {
	f := newFixture(t)
	for _, usernameOnly := range []bool{true, false} {
		cfg := f.config()
		if usernameOnly {
			cfg.VirtualUsername = "viewer"
		} else {
			cfg.VirtualPassword = "viewer-password"
		}
		if _, err := New(cfg, nil); err == nil {
			t.Fatal("accepted an incomplete virtual account")
		}
	}
	cfg := f.config()
	cfg.VirtualUsername, cfg.VirtualPassword = cfg.Username, cfg.Password
	if _, err := New(cfg, nil); err != nil {
		t.Fatal("matching source and virtual credentials must remain supported:", err)
	}
}

func TestVirtualDigestRejectsOtherCredentialsAndDeliversMedia(t *testing.T) {
	f := newFixture(t)
	cfg := f.config()
	cfg.VirtualUsername, cfg.VirtualPassword = "viewer", "viewer-password"
	s := startProxy(t, cfg)
	await(t, func() bool {
		status := s.Status()
		return status.Profiles["stream1"].State == "ready" && status.Profiles["stream2"].State == "ready"
	})
	for _, credentials := range [][2]string{{"", ""}, {"viewer", "wrong-password"}, {cfg.Username, cfg.Password}} {
		func() {
			u, _ := base.ParseURL("rtsp://" + s.Addr() + "/stream1")
			if credentials[0] != "" {
				u.User = url.UserPassword(credentials[0], credentials[1])
			}
			client := &gortsplib.Client{Scheme: u.Scheme, Host: u.Host, ReadTimeout: time.Second}
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, res, err := client.Describe(u)
			if err == nil || res == nil || res.StatusCode != base.StatusUnauthorized {
				t.Fatal("unaccepted downstream credentials did not receive 401")
			}
		}()
	}
	for _, path := range []string{"/stream1", "/stream2"} {
		func() {
			u, _ := base.ParseURL("rtsp://" + s.Addr() + path)
			u.User = url.UserPassword(cfg.VirtualUsername, cfg.VirtualPassword)
			tcp := gortsplib.ProtocolTCP
			client := &gortsplib.Client{Scheme: u.Scheme, Host: u.Host, Protocol: &tcp, ReadTimeout: time.Second}
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			desc, _, err := client.Describe(u)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.SetupAll(desc.BaseURL, desc.Medias); err != nil {
				t.Fatal(err)
			}
			packets := make(chan description.MediaType, 16)
			client.OnPacketRTPAny(func(media *description.Media, _ format.Format, _ *rtp.Packet) {
				select {
				case packets <- media.Type:
				default:
				}
			})
			if _, err := client.Play(nil); err != nil {
				t.Fatal(err)
			}
			seen := map[description.MediaType]bool{}
			deadline := time.After(2 * time.Second)
			for len(seen) < 2 {
				select {
				case kind := <-packets:
					seen[kind] = true
				case <-deadline:
					t.Fatal("authenticated reader did not receive video and audio")
				}
			}
		}()
	}
	if s.Status().AuthFailed {
		t.Fatal("downstream rejection latched the unrelated upstream workers")
	}
}

func TestVirtualDigestChecksEveryMediaRequest(t *testing.T) {
	f := newFixture(t)
	cfg := f.config()
	cfg.VirtualUsername, cfg.VirtualPassword = "viewer", "viewer-password"
	s := startProxy(t, cfg)
	await(t, func() bool { return s.Status().Profiles["stream1"].State == "ready" })
	netConn, err := net.DialTimeout("tcp", s.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer netConn.Close()
	if err := netConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := conn.NewConn(bufio.NewReader(netConn), netConn)
	streamURL, _ := base.ParseURL("rtsp://" + s.Addr() + "/stream1")
	trackURL, _ := base.ParseURL("rtsp://" + s.Addr() + "/stream1/trackID=0")
	var sequence int
	exchange := func(method base.Method, target *base.URL, header base.Header, sender *auth.Sender) *base.Response {
		t.Helper()
		sequence++
		if header == nil {
			header = make(base.Header)
		}
		header["CSeq"] = base.HeaderValue{strconv.Itoa(sequence)}
		request := &base.Request{Method: method, URL: target, Header: header}
		if sender != nil {
			sender.AddAuthorization(request)
		}
		if err := wire.WriteRequest(request); err != nil {
			t.Fatal(err)
		}
		response, err := wire.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	challenge := exchange(base.Describe, streamURL, nil, nil)
	if challenge.StatusCode != base.StatusUnauthorized || len(challenge.Header["WWW-Authenticate"]) != 1 {
		t.Fatal("expected one Digest challenge")
	}
	header := challenge.Header["WWW-Authenticate"][0]
	if !strings.HasPrefix(header, "Digest ") || strings.Contains(header, "Basic") || !strings.Contains(header, "algorithm=\"MD5\"") {
		t.Fatal("challenge must advertise Digest MD5 only")
	}
	sender := &auth.Sender{WWWAuth: challenge.Header["WWW-Authenticate"], User: cfg.VirtualUsername, Pass: cfg.VirtualPassword}
	if err := sender.Initialize(); err != nil {
		t.Fatal(err)
	}
	if got := exchange(base.Describe, streamURL, nil, sender); got.StatusCode != base.StatusOK {
		t.Fatalf("authenticated DESCRIBE status: %d", got.StatusCode)
	}
	transport := func() base.Header {
		return base.Header{"Transport": {"RTP/AVP/TCP;unicast;interleaved=0-1;encrypt=1;encryptVersion=1;keyVersion=1;smart_pkg_ver=2"}}
	}
	if got := exchange(base.Setup, trackURL, transport(), nil); got.StatusCode != base.StatusUnauthorized {
		t.Fatalf("anonymous SETUP after authenticated DESCRIBE status: %d", got.StatusCode)
	}
	setup := exchange(base.Setup, trackURL, transport(), sender)
	if setup.StatusCode != base.StatusOK || len(setup.Header["Session"]) != 1 {
		t.Fatalf("authenticated SETUP status: %d", setup.StatusCode)
	}
	if len(setup.Header["Transport"]) != 1 || !strings.Contains(setup.Header["Transport"][0], "interleaved=0-1") ||
		!strings.HasSuffix(setup.Header["Transport"][0], ";encrypt=0") {
		t.Fatal("native transport negotiation did not preserve channels and explicitly select unencrypted RTP")
	}
	session, _, _ := strings.Cut(setup.Header["Session"][0], ";")
	if got := exchange(base.Play, streamURL, base.Header{"Session": {session}}, nil); got.StatusCode != base.StatusUnauthorized {
		t.Fatalf("anonymous PLAY after authenticated SETUP status: %d", got.StatusCode)
	}
	if got := exchange(base.Play, streamURL, base.Header{"Session": {session}}, sender); got.StatusCode != base.StatusOK {
		t.Fatalf("authenticated PLAY status: %d", got.StatusCode)
	}
}
