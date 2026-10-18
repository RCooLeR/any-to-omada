// Package config validates a fixed source inventory and independently addressed
// virtual lenses without contacting cameras or resolving secrets.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
)

// Account holds references only; passwords never belong in the configuration.
type Account struct {
	Username     string `json:"username"`
	PasswordFile string `json:"password_file,omitempty"`
	PasswordEnv  string `json:"password_env,omitempty"`
}

// Event adapters for physical sources.
const (
	ProtocolDVRIP = "dvrip"
	ProtocolISAPI = "isapi"
	ProtocolONVIF = "onvif"
)

// brandProtocols maps each supported brand to its event adapter. Brands not
// listed can use "onvif" when the camera offers ONVIF events.
var brandProtocols = map[string]string{
	"imou": ProtocolDVRIP, "dahua": ProtocolDVRIP, "amcrest": ProtocolDVRIP,
	"hikvision": ProtocolISAPI, "annke": ProtocolISAPI,
	"reolink": ProtocolONVIF, "axis": ProtocolONVIF, "hanwha": ProtocolONVIF, "uniview": ProtocolONVIF,
	"tapo": ProtocolONVIF, "bosch": ProtocolONVIF, "vivotek": ProtocolONVIF, "foscam": ProtocolONVIF, "onvif": ProtocolONVIF,
}

// EventProtocol names the source's event adapter, or "" for an unsupported brand.
// NativePort is that adapter's port: DVRIP (37777), ISAPI HTTP (80) or the
// ONVIF HTTP service (80; Reolink 8000, Tapo 2020).
func (s Source) EventProtocol() string { return brandProtocols[s.Brand] }

// Source is one physical device with exactly one native event subscription.
type Source struct {
	ID            string                 `json:"id"`
	Enabled       bool                   `json:"enabled"`
	Brand         string                 `json:"brand"`
	Host          string                 `json:"host"`
	NativePort    int                    `json:"native_port"`
	Account       Account                `json:"account"`
	EventMappings []cameraevents.Mapping `json:"event_mappings,omitempty"`
}

// Compatibility enables bounded recorder-compatibility experiments for one
// virtual camera. Every option is off by default. Enabled options advertise
// configuration, services or identity fields that the physical source does not
// expose; they describe the virtual camera, never the source, and exist to
// isolate which recorder expectation blocks stream creation.
type Compatibility struct {
	// ModuleSpecProfile selects the advertised function.module_spec set: empty
	// or "minimal" (implemented features only) or "omada-ipc-observed" (the
	// capability set observed from an Omada 8MP Turret, firmware 1.0.7).
	ModuleSpecProfile string `json:"module_spec_profile,omitempty"`
	// AdvertiseVHTTPD reports the native vhttpd 8800 service in CET and UPnP
	// without a listener; the recorder opened no 8800 connection in captures.
	AdvertiseVHTTPD bool `json:"advertise_vhttpd,omitempty"`
	// ExtendedVideoFields adds the donor's optional encoder leaves with virtual values.
	ExtendedVideoFields bool `json:"extended_video_fields,omitempty"`
	// ExtendedIdentity adds hardware version, counts and stable virtual identifiers.
	ExtendedIdentity bool `json:"extended_identity,omitempty"`
	// ManufacturerName overrides the reported manufacturer; empty keeps AnyToOmada.
	ManufacturerName string `json:"manufacturer_name,omitempty"`
	// EncodeHTTPStrings percent-encodes HTTPS response string values as the
	// native camera does; native passthrough responses are always encoded.
	EncodeHTTPStrings bool `json:"encode_http_strings,omitempty"`
	// Network adds the virtual interface's netmask, gateway and DNS to wan_status.
	Network *CompatibilityNetwork `json:"network,omitempty"`
	// InStreamMarkers adds the native camera's per-frame TP-Link marker SEI
	// unit to forwarded video, with an intrusion rule alert while a forwarded
	// classified intrusion is open. No target boxes are added.
	InStreamMarkers bool `json:"in_stream_markers,omitempty"`
	// PTZModuleSpecKeys adds candidate function.module_spec keys with value
	// "1" to find which ones make the recorder offer PTZ controls. Requires a
	// configured ptz block; the keys come from a fixed allowlist.
	PTZModuleSpecKeys []string `json:"ptz_module_spec_keys,omitempty"`
}

// PTZ forwards recorder pan/tilt, zoom and preset commands to the physical
// source's ONVIF PTZ service with the source account. Omitted keeps PTZ
// unsupported.
type PTZ struct {
	// ONVIFPort is the source's ONVIF HTTP port (Imou and Dahua use 80).
	ONVIFPort int `json:"onvif_port"`
	// ProfileToken is this lens's ONVIF media profile, which carries its PTZ node.
	ProfileToken string `json:"profile_token"`
	// MaxMoveSeconds bounds a movement that receives no stop; default 10.
	MaxMoveSeconds int `json:"max_move_seconds,omitempty"`
}

// CompatibilityNetwork describes the virtual interface's IPv4 network.
type CompatibilityNetwork struct {
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
	DNS     string `json:"dns"`
}

// Camera is a virtual identity for one independently verified source channel.
// AdvertisedIP is never used as a listen address or upstream redirect.
// Lens "channel" records a verified mapping without claiming fixed or PTZ mechanics.
type Camera struct {
	ID                string `json:"id"`
	Enabled           bool   `json:"enabled"`
	Verified          bool   `json:"verified"`
	SourceID          string `json:"source_id"`
	SourceIndex       int    `json:"source_index"`
	Lens              string `json:"lens"`
	AdvertisedIP      string `json:"advertised_ip"`
	RecorderIP        string `json:"recorder_ip"`
	ManagementAddress string `json:"management_address"`
	RTSPAddress       string `json:"rtsp_address"`
	// AllowedTransportPeers optionally limits clients by IP; empty allows any peer.
	AllowedTransportPeers []string `json:"allowed_transport_peers,omitempty"`
	MainURL               string   `json:"main_url"`
	SubURL                string   `json:"sub_url"`
	Account               Account  `json:"account"`
	TLSCertificateFile    string   `json:"tls_certificate_file"`
	TLSKeyFile            string   `json:"tls_key_file"`
	// Compatibility holds optional recorder-compatibility experiments; omitted
	// means implemented features and source facts only.
	Compatibility Compatibility `json:"compatibility,omitempty"`
	// PTZ enables recorder PTZ control of a lens marked "ptz".
	PTZ *PTZ `json:"ptz,omitempty"`
	// WhiteLight and AlarmOutput enable explicit loopback tests only. They do
	// not advertise unverified controls to the recorder.
	WhiteLight  *WhiteLight  `json:"white_light,omitempty"`
	AlarmOutput *AlarmOutput `json:"alarm_output,omitempty"`
}

// Storage bounds retained JSONL payloads across process restarts.
type Storage struct {
	Directory    string `json:"directory"`
	SegmentBytes int64  `json:"segment_bytes"`
	Segments     int    `json:"segments"`
}

// Config is independent of the NVR bridge and research collector.
type Config struct {
	ControlAddress string   `json:"control_address"`
	Storage        Storage  `json:"storage"`
	Sources        []Source `json:"sources"`
	Cameras        []Camera `json:"cameras"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var environment = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// Load reads one strict JSON object, without returning private config content in errors.
func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("open translator configuration failed")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil {
		return cfg, errors.New("invalid translator configuration")
	}
	if d.Decode(new(any)) != io.EOF {
		return cfg, errors.New("configuration must contain one JSON object")
	}
	return cfg, cfg.Validate()
}

// Validate rejects ambiguous lens routing, duplicate listeners and invalid peers.
func (c Config) Validate() error {
	host, _, err := address(c.ControlAddress)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("control address must be explicit IPv4 loopback")
	}
	if c.Storage.Directory == "" || c.Storage.SegmentBytes < 4<<20 || c.Storage.SegmentBytes > 64<<20 || c.Storage.Segments < 2 || c.Storage.Segments > 64 {
		return errors.New("storage requires a directory, 4–64 MiB segments and 2–64 retained segments")
	}
	if len(c.Sources) == 0 || len(c.Sources) > 32 || len(c.Cameras) == 0 || len(c.Cameras) > 32 {
		return errors.New("configure between one and 32 sources and virtual cameras")
	}
	sources := map[string]Source{}
	hosts := map[string]bool{}
	for _, s := range c.Sources {
		if !identifier.MatchString(s.ID) || sources[s.ID].ID != "" || !validIP(s.Host) || hosts[s.Host] {
			return errors.New("sources require unique safe IDs and explicit IPv4 hosts")
		}
		if s.EventProtocol() == "" {
			return errors.New("source brand has no implemented adapter")
		}
		if len(s.EventMappings) > 0 && s.EventProtocol() != ProtocolDVRIP {
			return errors.New("intelligent event mappings apply to DVRIP sources only")
		}
		if s.NativePort < 1 || s.NativePort > 65535 || s.Account.validate() != nil {
			return errors.New("source port or credential reference is invalid")
		}
		for _, m := range s.EventMappings {
			if m.DeviceID != s.ID {
				return errors.New("event mappings must be scoped to their physical source")
			}
		}
		if _, err := cameraevents.Normalize(s.ID, time.Now(), map[string]any{}, s.EventMappings); err != nil {
			return errors.New("invalid source event mapping")
		}
		sources[s.ID], hosts[s.Host] = s, true
	}
	ids, vips, lenses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	listeners := []string{c.ControlAddress}
	for _, v := range c.Cameras {
		s, found := sources[v.SourceID]
		if !identifier.MatchString(v.ID) || ids[v.ID] || !found || v.SourceIndex < 0 || v.SourceIndex > 65535 {
			return errors.New("virtual cameras require unique IDs and a known source/lens index")
		}
		if v.Lens != "fixed" && v.Lens != "ptz" && v.Lens != "channel" && v.Lens != "unverified" {
			return errors.New("lens must be fixed, ptz, channel or unverified")
		}
		if v.Enabled && (!s.Enabled || !v.Verified || v.Lens == "unverified") {
			return errors.New("enabled cameras require an enabled source and verified lens mapping")
		}
		if !validIP(v.AdvertisedIP) || vips[v.AdvertisedIP] || !validIP(v.RecorderIP) || v.AdvertisedIP == v.RecorderIP {
			return errors.New("virtual cameras require unique advertised IPv4 addresses and a distinct logical recorder")
		}
		lens := fmt.Sprintf("%s/%d", v.SourceID, v.SourceIndex)
		if lenses[lens] {
			return errors.New("a physical lens may have only one virtual identity")
		}
		if v.Account.validate() != nil || v.TLSCertificateFile == "" || v.TLSKeyFile == "" {
			return errors.New("virtual accounts and TLS file references are required")
		}
		if err := v.Compatibility.validate(); err != nil {
			return err
		}
		if err := v.validatePTZ(); err != nil {
			return err
		}
		if err := v.validateControls(s); err != nil {
			return err
		}
		if len(v.AllowedTransportPeers) > 8 {
			return errors.New("configure at most eight exact transport peers per camera")
		}
		peers := map[string]bool{}
		for _, peer := range v.AllowedTransportPeers {
			if !validIP(peer) || peers[peer] {
				return errors.New("transport peers must be unique explicit IPv4 addresses")
			}
			peers[peer] = true
		}
		for _, listener := range []string{v.ManagementAddress, v.RTSPAddress} {
			if _, _, err := address(listener); err != nil {
				return errors.New("camera listeners require an explicit IPv4 bind address and port")
			}
			for _, other := range listeners {
				if overlaps(listener, other) {
					return errors.New("camera listeners overlap another listener")
				}
			}
			listeners = append(listeners, listener)
		}
		if v.MainURL != "" || v.SubURL != "" || v.Enabled {
			main, err := StreamURL(v.MainURL, s.Host)
			if err != nil {
				return err
			}
			sub, err := StreamURL(v.SubURL, s.Host)
			if err != nil || main.Host != sub.Host || v.MainURL == v.SubURL {
				return errors.New("main/sub require distinct URLs on one physical source RTSP port")
			}
		}
		ids[v.ID], vips[v.AdvertisedIP], lenses[lens] = true, true, true
	}
	return nil
}

var printableName = regexp.MustCompile(`^[ -~]{1,64}$`)
var profileToken = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// ptzModuleSpecCandidates are the keys tried for the recorder's PTZ
// capability bit: the camera firmware's pan/tilt motor key and the recorder's
// own capability names.
var ptzModuleSpecCandidates = map[string]bool{"motor": true, "ptz": true, "preset": true, "ptz_preset": true}

func (v Camera) validatePTZ() error {
	if v.PTZ == nil {
		if len(v.Compatibility.PTZModuleSpecKeys) > 0 {
			return errors.New("compatibility ptz_module_spec_keys requires a ptz block")
		}
		return nil
	}
	if v.Lens != "ptz" || v.PTZ.ONVIFPort < 1 || v.PTZ.ONVIFPort > 65535 || !profileToken.MatchString(v.PTZ.ProfileToken) ||
		v.PTZ.MaxMoveSeconds < 0 || v.PTZ.MaxMoveSeconds > 60 {
		return errors.New("ptz requires a ptz lens, an ONVIF port, a profile token and at most 60 move seconds")
	}
	seen := map[string]bool{}
	for _, key := range v.Compatibility.PTZModuleSpecKeys {
		if !ptzModuleSpecCandidates[key] || seen[key] {
			return errors.New("compatibility ptz_module_spec_keys must be unique allowlisted keys")
		}
		seen[key] = true
	}
	return nil
}

func (c Compatibility) validate() error {
	if c.ModuleSpecProfile != "" && c.ModuleSpecProfile != "minimal" && c.ModuleSpecProfile != "omada-ipc-observed" {
		return errors.New("compatibility module_spec_profile must be minimal or omada-ipc-observed")
	}
	if c.ManufacturerName != "" && !printableName.MatchString(c.ManufacturerName) {
		return errors.New("compatibility manufacturer_name must be printable ASCII of at most 64 characters")
	}
	if c.Network != nil {
		mask := net.ParseIP(c.Network.Netmask).To4()
		if mask == nil || !validMask(mask) || !validIP(c.Network.Gateway) || !validIP(c.Network.DNS) {
			return errors.New("compatibility network requires an IPv4 netmask, gateway and DNS address")
		}
	}
	return nil
}

// validMask accepts contiguous IPv4 masks between /8 and /30.
func validMask(mask net.IP) bool {
	ones, bits := net.IPMask(mask).Size()
	return bits == 32 && ones >= 8 && ones <= 30
}

func validIP(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && value != "255.255.255.255"
}

func address(value string) (string, int, error) {
	host, port, err := net.SplitHostPort(value)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 1 || n > 65535 || (host != "0.0.0.0" && !validIP(host)) {
		return "", 0, errors.New("invalid bind address")
	}
	return host, n, nil
}

func overlaps(a, b string) bool {
	ah, ap, _ := address(a)
	bh, bp, _ := address(b)
	return ap == bp && (ah == bh || ah == "0.0.0.0" || bh == "0.0.0.0")
}

// StreamURL pins credentials and all subsequent RTSP requests to one explicit origin.
func StreamURL(value, host string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "rtsp" || u.Hostname() != host || u.User != nil || u.Fragment != "" || u.Path == "" || len(value) > 2048 {
		return nil, errors.New("streams require credential-free RTSP URLs on the physical source host")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("stream URLs require an explicit port")
	}
	for key := range u.Query() {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "pass") || strings.Contains(lower, "token") || strings.Contains(lower, "auth") || strings.Contains(lower, "user") {
			return nil, errors.New("stream query cannot contain credentials")
		}
	}
	return u, nil
}

func (a Account) validate() error {
	if a.Username == "" || len(a.Username) > 128 || strings.ContainsAny(a.Username, "\r\n\x00") || (a.PasswordFile == "") == (a.PasswordEnv == "") || (a.PasswordEnv != "" && !environment.MatchString(a.PasswordEnv)) {
		return errors.New("invalid credential reference")
	}
	return nil
}

// Resolve returns a password only in memory. File contents are bounded to 4 KiB.
func (a Account) Resolve() (string, error) {
	if a.validate() != nil {
		return "", errors.New("invalid credential reference")
	}
	var password string
	if a.PasswordFile != "" {
		f, err := os.Open(a.PasswordFile)
		if err != nil {
			return "", errors.New("credential file unavailable")
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(data) > 4096 {
			return "", errors.New("credential file invalid")
		}
		password = strings.TrimRight(string(data), "\r\n")
	} else {
		password = os.Getenv(a.PasswordEnv)
	}
	if password == "" || len(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("credential reference is empty or invalid")
	}
	return password, nil
}
