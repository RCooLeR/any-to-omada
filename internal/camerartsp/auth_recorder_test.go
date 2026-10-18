package camerartsp

import (
	"bufio"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gortsplib/v5/pkg/auth"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/conn"
)

var reChallengeField = regexp.MustCompile(`(realm|nonce)="([^"]*)"`)

// TestVirtualDigestAcceptsRecorderPlayURIForm reproduces the recorder's PLAY:
// the request targets the DESCRIBE Content-Base (trailing slash) while the
// digest is computed over the stream URL without it. A foreign URI still fails.
func TestVirtualDigestAcceptsRecorderPlayURIForm(t *testing.T) {
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
	baseURL, _ := base.ParseURL("rtsp://" + s.Addr() + "/stream1/")
	trackURL, _ := base.ParseURL("rtsp://" + s.Addr() + "/stream1/trackID=0")
	var sequence int
	exchange := func(method base.Method, target *base.URL, header base.Header) *base.Response {
		t.Helper()
		sequence++
		if header == nil {
			header = make(base.Header)
		}
		header["CSeq"] = base.HeaderValue{strconv.Itoa(sequence)}
		if err := wire.WriteRequest(&base.Request{Method: method, URL: target, Header: header}); err != nil {
			t.Fatal(err)
		}
		response, err := wire.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	challenge := exchange(base.Describe, streamURL, nil)
	if challenge.StatusCode != base.StatusUnauthorized || len(challenge.Header["WWW-Authenticate"]) != 1 {
		t.Fatal("expected one Digest challenge")
	}
	fields := map[string]string{}
	for _, match := range reChallengeField.FindAllStringSubmatch(challenge.Header["WWW-Authenticate"][0], -1) {
		fields[match[1]] = match[2]
	}
	if fields["realm"] == "" || fields["nonce"] == "" {
		t.Fatal("challenge lacks realm or nonce")
	}
	signed := func(method base.Method, uri string) base.Header {
		ha1 := md5Hex(cfg.VirtualUsername + ":" + fields["realm"] + ":" + cfg.VirtualPassword)
		response := md5Hex(ha1 + ":" + fields["nonce"] + ":" + md5Hex(string(method)+":"+uri))
		return base.Header{"Authorization": {`Digest username="` + cfg.VirtualUsername + `", realm="` + fields["realm"] + `", nonce="` + fields["nonce"] + `", uri="` + uri + `", response="` + response + `"`}}
	}
	sender := &auth.Sender{WWWAuth: challenge.Header["WWW-Authenticate"], User: cfg.VirtualUsername, Pass: cfg.VirtualPassword}
	if err := sender.Initialize(); err != nil {
		t.Fatal(err)
	}
	describe := &base.Request{Method: base.Describe, URL: streamURL, Header: base.Header{}}
	sender.AddAuthorization(describe)
	if got := exchange(base.Describe, streamURL, describe.Header); got.StatusCode != base.StatusOK {
		t.Fatalf("authenticated DESCRIBE status: %d", got.StatusCode)
	}
	setupHeader := signed(base.Setup, trackURL.String())
	setupHeader["Transport"] = base.HeaderValue{"RTP/AVP/TCP;unicast;interleaved=0-1"}
	setup := exchange(base.Setup, trackURL, setupHeader)
	if setup.StatusCode != base.StatusOK || len(setup.Header["Session"]) != 1 {
		t.Fatalf("authenticated SETUP status: %d", setup.StatusCode)
	}
	session, _, _ := strings.Cut(setup.Header["Session"][0], ";")
	foreign := signed(base.Play, "rtsp://"+s.Addr()+"/stream2")
	foreign["Session"] = base.HeaderValue{session}
	if got := exchange(base.Play, baseURL, foreign); got.StatusCode != base.StatusUnauthorized || len(got.Header["WWW-Authenticate"]) != 1 {
		t.Fatalf("PLAY signed for another stream status: %d", got.StatusCode)
	}
	accepted := signed(base.Play, streamURL.String())
	accepted["Session"] = base.HeaderValue{session}
	accepted["Range"] = base.HeaderValue{"npt=0.000-"}
	if got := exchange(base.Play, baseURL, accepted); got.StatusCode != base.StatusOK {
		t.Fatalf("PLAY on Content-Base signed without trailing slash status: %d", got.StatusCode)
	}
}
