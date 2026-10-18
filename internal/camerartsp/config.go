// Package camerartsp exposes two fixed live profiles from one selected camera
// source. It relays encoded media without transcoding and can insert configured
// Omada event metadata without changing the encoded picture.
package camerartsp

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
)

// Config maps one explicitly selected lens's main/sub URLs to /stream1 and
// /stream2. URLs contain no credentials; the caller resolves protected secrets
// into Username/Password in memory. All upstream connections stay on one IP.
type Config struct {
	Address string
	// AllowedClientIPs optionally limits clients by IP; empty allows any peer.
	AllowedClientIPs []string
	UpstreamIP       string
	UpstreamPort     int
	MainURL          string `json:"-"`
	SubURL           string `json:"-"`
	Username         string `json:"-"`
	Password         string `json:"-"`
	// VirtualUsername and VirtualPassword authenticate downstream viewers with
	// Digest MD5. Both empty retain an anonymous frontend; otherwise both are required.
	VirtualUsername string `json:"-"`
	VirtualPassword string `json:"-"`
	MaxClients      int
	// Marker, when set, adds a TP-Link marker SEI unit to every forwarded H.264
	// or H.265 access unit, with content from the returned state.
	Marker         func() tpmarker.State `json:"-"`
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	RetryMin       time.Duration
	RetryMax       time.Duration
}

// validate applies zero-value limits and rejects ambiguous credentials, invalid
// endpoints and profile URLs outside the configured upstream origin.
func (c *Config) validate() error {
	listenHost, listenPort, err := net.SplitHostPort(c.Address)
	listenIP, parseErr := netip.ParseAddr(listenHost)
	port, portErr := strconv.Atoi(listenPort)
	if err != nil || parseErr != nil || (!validIP(listenIP) && listenHost != "0.0.0.0") || portErr != nil || port < 0 || port > 65535 {
		return errors.New("RTSP listener requires an explicit unicast IP and port")
	}
	if len(c.AllowedClientIPs) > 8 {
		return errors.New("RTSP allows at most eight explicit allowed peers")
	}
	for _, value := range append(append([]string{}, c.AllowedClientIPs...), c.UpstreamIP) {
		ip, err := netip.ParseAddr(value)
		if err != nil || !validIP(ip) {
			return errors.New("RTSP peers require explicit unicast IP addresses")
		}
	}
	if c.UpstreamPort == 0 {
		c.UpstreamPort = 554
	}
	if c.UpstreamPort < 1 || c.UpstreamPort > 65535 {
		return errors.New("RTSP upstream port is invalid")
	}
	for _, value := range []string{c.MainURL, c.SubURL} {
		u, err := base.ParseURL(value)
		if err != nil || u == nil || u.Scheme != "rtsp" || u.User != nil || u.Fragment != "" || u.Path == "" || !c.sameOrigin(u) {
			return errors.New("RTSP profiles require credential-free URLs at the configured upstream origin")
		}
	}
	if c.MainURL == c.SubURL {
		return errors.New("RTSP main and sub profiles require different source URLs")
	}
	if (c.VirtualUsername == "") != (c.VirtualPassword == "") {
		return errors.New("RTSP virtual username and password must be configured together")
	}
	if c.MaxClients == 0 {
		c.MaxClients = 8
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 20 * time.Second
	}
	if c.RetryMin == 0 {
		c.RetryMin = 15 * time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = time.Minute
	}
	if c.MaxClients < 1 || c.MaxClients > 64 || c.ConnectTimeout <= 0 || c.ConnectTimeout > time.Minute || c.ReadTimeout <= 0 || c.ReadTimeout > 5*time.Minute || c.RetryMin <= 0 || c.RetryMax < c.RetryMin || c.RetryMax > 5*time.Minute {
		return errors.New("RTSP client limits or timeouts are invalid")
	}
	return nil
}

// validIP excludes wildcard, multicast and IPv4 broadcast addresses from peers.
func validIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() != "255.255.255.255"
}

// origin returns the sole address the upstream dialer is permitted to contact.
func (c Config) origin() string { return net.JoinHostPort(c.UpstreamIP, strconv.Itoa(c.UpstreamPort)) }

// sameOrigin checks RTSP scheme, host and port, treating an omitted port as 554.
func (c Config) sameOrigin(u *base.URL) bool {
	if u == nil || u.Scheme != "rtsp" || u.Hostname() != c.UpstreamIP {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "554"
	}
	return port == strconv.Itoa(c.UpstreamPort)
}
