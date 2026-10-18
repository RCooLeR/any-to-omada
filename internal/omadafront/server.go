// Package omadafront implements the observed Omada HTTP management subset for a
// local camera experiment. A separately owned callback worker provides native
// authentication and alarm delivery when configured by the application.
package omadafront

import (
	"crypto/md5" // Required by the observed camera protocol, not password storage.
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const (
	unsupportedCode  = -40106
	unauthorizedCode = -40401
	maxBodyBytes     = 64 * 1024
	sessionBytes     = 16
)

// Config holds explicit proxy credentials and the address reported by the
// proxy. The caller owns TLS, listener allowlists and request timeouts.
type Config struct {
	Username string
	Password string
	IP       string
	// MAC is the virtual identity shared with the callback declaration. An
	// all-zero value means unknown and is omitted from management responses.
	MAC [6]byte
	// SessionTTL defaults to 15 minutes; allowed values are 1 minute to 1 hour.
	SessionTTL time.Duration
	// MaxSessions defaults to 32; allowed values are 1 to 256.
	MaxSessions int
	// Logger enables fixed-label request diagnostics; nil leaves them disabled.
	Logger *slog.Logger
	// StartCallback queues one authenticated recorder registration. It must not
	// block on dialing or authentication; the worker owns that service lifecycle.
	StartCallback func(CallbackRequest) error
	StopCallback  func(string, int)
	// Metadata supplies current source facts and the virtual software identity.
	Metadata func() Metadata
	// RTSPDigest advertises MD5 only when the caller enables it on the media listener.
	RTSPDigest bool
	// ClientCounts reports active downstream streams and distinct client IPs.
	// These discovery fields are runtime counts, not available profile counts.
	ClientCounts func() (streams, ips int)
	// Compatibility enables bounded recorder-compatibility experiments; the
	// zero value keeps implemented features and source facts only.
	Compatibility Compatibility
	// PTZ moves the source lens; nil keeps PTZ unsupported and unadvertised.
	PTZ PTZ
}

// CallbackRequest carries a fresh recorder-issued credential. It must never be
// logged, persisted or reused for another recorder or virtual camera.
type CallbackRequest struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Version  string `json:"version"`
	AuthCode string `json:"auth_code"`
}

// Status contains only bounded counters and fixed operation labels. It never
// contains credentials, session tokens, request paths or captured body fields.
type Status struct {
	Requests                uint64            `json:"requests"`
	LoginSuccesses          uint64            `json:"login_successes"`
	LoginFailures           uint64            `json:"login_failures"`
	Sessions                int               `json:"sessions"`
	Unsupported             map[string]uint64 `json:"unsupported"`
	NativeEventsImplemented bool              `json:"native_events_implemented"`
}

// Server is a concurrency-safe management handler with in-memory virtual
// settings and sessions. Configured callback and PTZ delegates can perform
// network operations; session expiry itself needs no background goroutine.
type Server struct {
	username       string
	passwordHash   string
	ip             string
	mac            string
	ttl            time.Duration
	maxSessions    int
	logger         *slog.Logger
	startCallback  func(CallbackRequest) error
	stopCallback   func(string, int)
	metadata       func() Metadata
	rtspDigest     bool
	clientCounts   func() (int, int)
	compat         Compatibility
	virtualTime    *virtualTimeState
	virtualImaging *virtualImagingState
	virtualDetect  *virtualDetectionState
	ptz            PTZ
	started        time.Time
	now            func() time.Time
	// mu guards sessions and status. No HTTP I/O occurs while it is held.
	mu       sync.Mutex
	sessions map[string]time.Time
	status   Status
}

// New validates configuration without echoing it and derives the observed
// uppercase MD5("TPCQ75NF2Y:" + password) login proof. The plaintext password is
// not retained by Server. This legacy proof is only appropriate behind TLS.
func New(cfg Config) (*Server, error) {
	if cfg.Username == "" || len(cfg.Username) > 128 || cfg.Password == "" || len(cfg.Password) > 1024 {
		return nil, errors.New("proxy credentials are missing or exceed limits")
	}
	ip, err := netip.ParseAddr(cfg.IP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, errors.New("proxy IP must be a specific IPv4 address")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 15 * time.Minute
	}
	if cfg.SessionTTL < time.Minute || cfg.SessionTTL > time.Hour {
		return nil, errors.New("session TTL must be between one minute and one hour")
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 32
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > 256 {
		return nil, errors.New("maximum sessions must be between one and 256")
	}
	hash := md5.Sum([]byte("TPCQ75NF2Y:" + cfg.Password))
	mac := ""
	if cfg.MAC != ([6]byte{}) {
		mac = strings.ReplaceAll(net.HardwareAddr(cfg.MAC[:]).String(), ":", "-")
	}
	server := &Server{username: cfg.Username, passwordHash: strings.ToUpper(hex.EncodeToString(hash[:])), ip: ip.String(), mac: mac,
		ttl: cfg.SessionTTL, maxSessions: cfg.MaxSessions, logger: cfg.Logger, started: time.Now(), now: time.Now,
		startCallback: cfg.StartCallback, stopCallback: cfg.StopCallback, metadata: cfg.Metadata, rtspDigest: cfg.RTSPDigest, clientCounts: cfg.ClientCounts, compat: cfg.Compatibility, ptz: cfg.PTZ,
		sessions: make(map[string]time.Time), status: Status{Unsupported: make(map[string]uint64), NativeEventsImplemented: cfg.StartCallback != nil}}
	server.virtualTime = newVirtualTimeState(func() time.Time { return server.now() })
	server.virtualImaging = newVirtualImagingState()
	server.virtualDetect = newVirtualDetectionState()
	return server, nil
}

// Status returns a detached snapshot and removes expired sessions.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(s.now())
	result := s.status
	result.Sessions = len(s.sessions)
	result.Unsupported = make(map[string]uint64, len(s.status.Unsupported))
	for name, count := range s.status.Unsupported {
		result.Unsupported[name] = count
	}
	return result
}

// expire removes sessions whose deadline has passed; the caller must hold s.mu.
func (s *Server) expire(now time.Time) {
	for token, until := range s.sessions {
		if !now.Before(until) {
			delete(s.sessions, token)
		}
	}
}

// ServeHTTP handles POST / and POST /stok=<generated-token>/ds, plus anonymous
// stream discovery at /stok=/ds. GET selector names refer to JSON operations,
// not the HTTP request method.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	diagnostic := &requestDiagnostic{ResponseWriter: w, operation: "unknown", authOutcome: "not_checked", pathKind: pathKind(r.URL.Path), discoveryShape: "not_applicable"}
	w = diagnostic
	if s.logger != nil {
		defer func() {
			fields := []any{"operation", diagnostic.operation, "auth_outcome", diagnostic.authOutcome,
				"http_status", diagnostic.httpStatus, "error_code", diagnostic.errorCode,
				"path_kind", diagnostic.pathKind, "discovery_shape", diagnostic.discoveryShape}
			if diagnostic.operation == "unsupported_read" {
				fields = append(fields, "read_modules", diagnostic.readModules,
					"read_selectors", diagnostic.readSelectors, "read_selector_forms", diagnostic.readSelectorForms,
					"unknown_read_modules", diagnostic.unknownReadModules)
			}
			if len(diagnostic.writeOperations) > 0 {
				fields = append(fields, "write_operations", diagnostic.writeOperations)
			}
			if len(diagnostic.requestShape) > 0 {
				fields = append(fields, "request_shape", diagnostic.requestShape)
			}
			s.logger.Info("camera management request", fields...)
		}()
	}
	s.mu.Lock()
	s.status.Requests++
	s.mu.Unlock()
	// Response headers follow the captured native camera; none carries request data.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// The native camera closes each HTTP/1.1 exchange, even when the NVR
	// requests keep-alive. Match its chunk framing and completion signal.
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Connection", "close")
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.write(w, http.StatusMethodNotAllowed, map[string]any{"error_code": unsupportedCode})
		return
	}
	if r.URL.RawQuery != "" || (r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/stok=")) {
		s.write(w, http.StatusNotFound, map[string]any{"error_code": unsupportedCode})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	var request map[string]json.RawMessage
	if decoder.Decode(&request) != nil || request == nil {
		s.write(w, http.StatusBadRequest, map[string]any{"error_code": unsupportedCode})
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		s.write(w, http.StatusBadRequest, map[string]any{"error_code": unsupportedCode})
		return
	}
	var method string
	if json.Unmarshal(request["method"], &method) != nil {
		s.write(w, http.StatusBadRequest, map[string]any{"error_code": unsupportedCode})
		return
	}
	diagnostic.operation = operationLabel(request, method)
	if method == "set" || diagnostic.operation == "system_write" || diagnostic.operation == "video_control" {
		diagnostic.writeOperations = writeOperationLabels(request)
	}
	if diagnostic.operation == "unsupported_read" {
		diagnostic.readModules = readModuleLabels(request)
		diagnostic.readSelectors, diagnostic.readSelectorForms, diagnostic.unknownReadModules = readSelectorLabels(request)
	}
	if diagnostic.operation == "stream_discovery" {
		diagnostic.discoveryShape = "other"
		if emptyJSONObject(request["get_rtsp_info"]) {
			diagnostic.discoveryShape = "empty_object"
		}
	}
	// The NVR probes stream counts with an empty stok before authenticating.
	if (r.URL.Path == "/" || r.URL.Path == "/stok=/ds") && method == "do" && len(request) == 2 {
		if raw, ok := request["get_rtsp_info"]; ok && emptyJSONObject(raw) {
			diagnostic.authOutcome = "anonymous"
			s.write(w, http.StatusOK, s.streamDiscovery())
			return
		}
	}
	if r.URL.Path == "/" && method == "do" && len(request) == 2 {
		if raw, ok := request["login"]; ok {
			diagnostic.authOutcome = s.login(w, raw)
			return
		}
		if raw, ok := request["user_management"]; ok && encryptInfoRequest(raw) {
			diagnostic.authOutcome = "required"
			s.challenge(w)
			return
		}
	}
	if !s.authorized(r.URL.Path) {
		diagnostic.authOutcome = "required"
		s.challenge(w)
		return
	}
	diagnostic.authOutcome = "authenticated"
	if s.ptz != nil && isPTZRequest(request) {
		diagnostic.requestShape = requestShape(request)
		if response, ok := s.ptzRequest(r.Context(), method, request); ok {
			diagnostic.operation = "ptz_control"
			s.write(w, http.StatusOK, response)
			return
		}
	}
	if method == "do" && s.callback(w, request) {
		return
	}
	if method == "get" {
		if response, ok := s.read(request); ok {
			diagnostic.operation = successfulReadLabel(request)
			s.write(w, http.StatusOK, response)
			return
		}
	}
	if s.virtualTime.write(method, request) || s.virtualImaging.write(method, request) || s.virtualDetect.write(method, request) {
		s.write(w, http.StatusOK, map[string]any{"error_code": 0})
		return
	}
	s.unsupported(request, method)
	diagnostic.requestShape = requestShape(request)
	s.write(w, http.StatusOK, map[string]any{"error_code": unsupportedCode})
}

// emptyJSONObject accepts exactly an empty JSON object, excluding null.
func emptyJSONObject(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && fields != nil && len(fields) == 0
}

// encryptInfoRequest recognizes only the observed get_encrypt_info:null
// shape, excluding extra operations or alternate parameter forms.
func encryptInfoRequest(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 1 {
		return false
	}
	value, ok := fields["get_encrypt_info"]
	return ok && string(value) == "null"
}

// challenge writes the observed legacy MD5 authentication challenge without
// advertising unimplemented encryption methods.
func (s *Server) challenge(w http.ResponseWriter) {
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		s.write(w, http.StatusServiceUnavailable, map[string]any{"error_code": unsupportedCode})
		return
	}
	// Only the observed legacy proof is implemented. Do not advertise RSA,
	// DAC or PAKE support using copied challenge material from a real camera.
	s.write(w, http.StatusUnauthorized, map[string]any{"error_code": unauthorizedCode, "device_type": "SECUR.CONSUMER.IPC",
		"data": map[string]any{"code": -40407, "encrypt_type": []string{"1"}, "passwdType": "md5", "nonce": hex.EncodeToString(nonce[:]), "secVersion": "1.0"}})
}

// login verifies the legacy proof, allocates a bounded expiring session and
// writes the response; its returned label describes proof acceptance only.
func (s *Server) login(w http.ResponseWriter, raw json.RawMessage) string {
	var login struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		PasswordType string `json:"passwdType"`
		EncryptType  string `json:"encrypt_type"`
	}
	err := json.Unmarshal(raw, &login)
	username, decodeErr := url.PathUnescape(login.Username)
	valid := err == nil && decodeErr == nil && login.PasswordType == "md5" && (login.EncryptType == "" || login.EncryptType == "1") &&
		subtle.ConstantTimeCompare([]byte(username), []byte(s.username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(login.Password), []byte(s.passwordHash)) == 1
	if !valid {
		s.mu.Lock()
		s.status.LoginFailures++
		s.mu.Unlock()
		s.challenge(w)
		return "rejected"
	}
	var random [sessionBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		s.write(w, http.StatusServiceUnavailable, map[string]any{"error_code": unsupportedCode})
		return "accepted"
	}
	token := hex.EncodeToString(random[:])
	now := s.now()
	s.mu.Lock()
	s.expire(now)
	if len(s.sessions) >= s.maxSessions {
		s.mu.Unlock()
		s.write(w, http.StatusServiceUnavailable, map[string]any{"error_code": unsupportedCode})
		return "accepted"
	}
	s.sessions[token] = now.Add(s.ttl)
	s.status.LoginSuccesses++
	s.mu.Unlock()
	s.write(w, http.StatusOK, map[string]any{"user_group": "root", "stok": token, "error_code": 0})
	return "accepted"
}

// authorized checks an exact session URL and removes expired sessions without
// renewing their lifetime.
func (s *Server) authorized(path string) bool {
	if len(path) != len("/stok=")+sessionBytes*2+len("/ds") || !strings.HasPrefix(path, "/stok=") || !strings.HasSuffix(path, "/ds") {
		return false
	}
	token := strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds")
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expire(now)
	until, ok := s.sessions[token]
	return ok && now.Before(until)
}

// read resolves a bounded set of selectors against one metadata snapshot;
// unknown sections are omitted, and an entirely unsupported read returns false.
func (s *Server) read(request map[string]json.RawMessage) (map[string]any, bool) {
	if len(request) < 2 || len(request) > 17 {
		return nil, false
	}
	metadata := Metadata{}
	if s.metadata != nil {
		metadata = s.metadata()
	}
	response := map[string]any{}
	for module, raw := range request {
		if module == "method" {
			continue
		}
		var selector map[string]json.RawMessage
		if json.Unmarshal(raw, &selector) != nil || len(selector) == 0 || len(selector) > 3 {
			return nil, false
		}
		if version, present := selector["version"]; present {
			var value string
			if json.Unmarshal(version, &value) != nil || value != "1" || len(selector) == 1 {
				return nil, false
			}
		}
		sections := map[string]any{}
		for kind, values := range selector {
			if kind == "version" {
				continue
			}
			if kind != "name" && kind != "table" {
				return nil, false
			}
			names, ok := selectorNames(values)
			if !ok {
				return nil, false
			}
			for _, name := range names {
				if kind == "table" {
					if module == "upnpc" && name == "upnp_status" {
						sections[name] = s.upnpServiceStatus()
					} else if rows, ok := s.virtualDetect.table(module, name); ok {
						sections[name] = rows
					}
				} else if body, supported := s.readSection(module, name, metadata); supported {
					sections[name] = body
				}
			}
		}
		if len(sections) > 0 {
			response[module] = sections
		}
	}
	if len(response) == 0 {
		return nil, false
	}
	response["error_code"] = 0
	return response, true
}

// successfulReadLabel categorizes a completed read using fixed names,
// including multi-module responses, without retaining request values.
func successfulReadLabel(request map[string]json.RawMessage) string {
	label := operationLabel(request, "get")
	if label != "unsupported_read" {
		return label
	}
	if len(request) == 2 {
		for module, name := range map[string]string{"device_info": "device_identity", "video": "video_settings", "cet": "service_ports", "upnpc": "upnp_status"} {
			if _, ok := request[module]; ok {
				return name
			}
		}
	}
	return "management_read"
}

// unsupported increments a fixed operation category under the status lock,
// never storing arbitrary request fields.
func (s *Server) unsupported(request map[string]json.RawMessage, method string) {
	// Fixed labels prevent attacker-controlled keys or credentials becoming logs.
	label := "unknown"
	if method == "set" {
		label = "settings_write"
	}
	if method == "get" {
		label = "unsupported_read"
	}
	if method == "do" {
		for module, expected := range map[string]string{"nvr_long_connect": "nvr_long_connect", "system": "system_write", "video": "video_control"} {
			if _, ok := request[module]; ok {
				label = expected
				break
			}
		}
	}
	s.mu.Lock()
	s.status.Unsupported[label]++
	s.mu.Unlock()
}

// write optionally percent-encodes string values like the native camera before
// sending; the diagnostic error code always comes from the unencoded value.
func (s *Server) write(w http.ResponseWriter, status int, value any) {
	if s.compat.EncodeHTTPStrings {
		if raw, err := json.Marshal(value); err == nil {
			if coded, err := omadalink.EncodeResponseStrings(raw); err == nil {
				writeBody(w, status, value, coded)
				return
			}
		}
	}
	writeJSON(w, status, value)
}

// writeJSON sends an unencoded JSON response and records its diagnostic code.
func writeJSON(w http.ResponseWriter, status int, value any) { writeBody(w, status, value, nil) }

// writeBody records response status before writing JSON or pre-encoded JSON;
// a disconnected client terminates the response without logging its payload.
func writeBody(w http.ResponseWriter, status int, value any, encoded []byte) {
	if diagnostic, ok := w.(*requestDiagnostic); ok {
		diagnostic.httpStatus = status
		if fields, ok := value.(map[string]any); ok {
			if code, ok := fields["error_code"].(int); ok {
				diagnostic.errorCode = code
			}
		}
	}
	w.WriteHeader(status)
	// All response values are built-in JSON types. A write failure is the
	// disconnected request's terminal condition; no private payload is logged.
	if encoded != nil {
		_, _ = w.Write(append(encoded, '\n'))
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

// requestDiagnostic wraps one response with bounded diagnostic labels and
// status fields; it must not retain request credentials or session tokens.
type requestDiagnostic struct {
	http.ResponseWriter
	operation          string
	authOutcome        string
	httpStatus         int
	errorCode          int
	pathKind           string
	discoveryShape     string
	readModules        []string
	readSelectors      []string
	readSelectorForms  []string
	unknownReadModules int
	writeOperations    []string
	requestShape       []string
}

// pathKind classifies paths without retaining a session token or arbitrary text.
func pathKind(path string) string {
	switch {
	case path == "/":
		return "root"
	case path == "/stok=/ds":
		return "empty_session"
	case strings.HasPrefix(path, "/stok=") && strings.HasSuffix(path, "/ds") && !strings.Contains(strings.TrimSuffix(strings.TrimPrefix(path, "/stok="), "/ds"), "/"):
		return "session"
	default:
		return "other"
	}
}

// operationLabel classifies request operations using fixed labels before
// dispatch; unsupported_read can be refined after a successful read.
func operationLabel(request map[string]json.RawMessage, method string) string {
	switch method {
	case "set":
		return "settings_write"
	case "get":
		if len(request) == 2 {
			for _, selector := range []struct{ module, name, label string }{
				{"function", "module_spec", "capabilities"},
				{"network", "wan_status", "network_status"},
				{"system", "time_status", "time_status"},
			} {
				var fields struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(request[selector.module], &fields) == nil && fields.Name == selector.name {
					return selector.label
				}
			}
		}
		return "unsupported_read"
	case "do":
		if len(request) != 2 {
			return "unknown"
		}
		if _, ok := request["get_rtsp_info"]; ok {
			return "stream_discovery"
		}
		if _, ok := request["login"]; ok {
			return "login"
		}
		if encryptInfoRequest(request["user_management"]) {
			return "auth_challenge"
		}
		if raw, ok := request["nvr_long_connect"]; ok {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) == nil && len(fields) == 1 {
				if _, ok := fields["nvr_connect_start"]; ok {
					return "callback_registration"
				}
			}
		}
		if _, ok := request["video"]; ok {
			return "video_control"
		}
		if _, ok := request["system"]; ok {
			return "system_write"
		}
	}
	return "unknown"
}
