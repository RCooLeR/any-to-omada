package camerartsp

import (
	"crypto/md5" // Digest MD5 is the recorder-facing RTSP authentication method.
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/auth"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/headers"
)

// digestRealm matches the realm gortsplib advertised before this verifier
// replaced it, so previously working clients see an unchanged challenge.
const digestRealm = "IPCAM"

// authorize returns nil when the request carries valid virtual-account Digest
// MD5 credentials, otherwise the 401 response to send. A frontend without a
// virtual account stays anonymous. The nonce is per connection and challenges
// are repeated for wrong credentials instead of closing the connection.
func (s *Server) authorize(connection *gortsplib.ServerConn, request *base.Request) *base.Response {
	if s.cfg.VirtualUsername == "" {
		return nil
	}
	nonce, err := s.nonce(connection)
	if err != nil {
		return &base.Response{StatusCode: base.StatusInternalServerError}
	}
	reason := s.verifyDigest(request, nonce)
	if reason == "" {
		return nil
	}
	s.logAuthorizationFailure(request, reason)
	return &base.Response{StatusCode: base.StatusUnauthorized, Header: base.Header{
		"WWW-Authenticate": auth.GenerateWWWAuthenticate([]auth.VerifyMethod{auth.VerifyMethodDigestMD5}, digestRealm, nonce),
	}}
}

func (s *Server) nonce(connection *gortsplib.ServerConn) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nonces == nil {
		s.nonces = make(map[*gortsplib.ServerConn]string)
	}
	if nonce, ok := s.nonces[connection]; ok {
		return nonce, nil
	}
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return "", err
	}
	s.nonces[connection] = nonce
	return nonce, nil
}

// verifyDigest returns an empty string for valid credentials or a fixed reason
// label. The response hash is computed over the URI the client actually signed.
func (s *Server) verifyDigest(request *base.Request, nonce string) string {
	values := request.Header["Authorization"]
	if len(values) == 0 {
		return "no_credentials"
	}
	var credentials headers.Authorization
	if credentials.Unmarshal(values) != nil {
		return "malformed"
	}
	if credentials.Method != headers.AuthMethodDigest || (credentials.Algorithm != nil && *credentials.Algorithm != headers.AuthAlgorithmMD5) {
		return "unsupported_method"
	}
	if credentials.Nonce != nonce {
		return "stale_nonce"
	}
	if credentials.Realm != digestRealm {
		return "wrong_realm"
	}
	if subtle.ConstantTimeCompare([]byte(credentials.Username), []byte(s.cfg.VirtualUsername)) != 1 {
		return "wrong_user"
	}
	if !digestURIAccepted(request, credentials.URI) {
		return "uri_mismatch"
	}
	ha1 := md5Hex(s.cfg.VirtualUsername + ":" + digestRealm + ":" + s.cfg.VirtualPassword)
	ha2 := md5Hex(string(request.Method) + ":" + credentials.URI)
	expected := []string{md5Hex(ha1 + ":" + nonce + ":" + ha2)}
	if credentials.Qop != nil && *credentials.Qop == "auth" && credentials.Nc != nil && credentials.Cnonce != nil {
		expected = append(expected, md5Hex(ha1+":"+nonce+":"+*credentials.Nc+":"+*credentials.Cnonce+":auth:"+ha2))
	}
	received := []byte(strings.ToLower(credentials.Response))
	for _, candidate := range expected {
		if subtle.ConstantTimeCompare(received, []byte(candidate)) == 1 {
			return ""
		}
	}
	return "wrong_response"
}

// digestURIAccepted accepts the absolute request URL or its request URI, each
// with or without a trailing slash, and for SETUP the stream base URL. The
// recorder issues PLAY on the DESCRIBE Content-Base (trailing slash) while
// signing the URI without it; the native camera accepts that form.
func digestURIAccepted(request *base.Request, received string) bool {
	if request.URL == nil || received == "" {
		return false
	}
	candidates := []string{request.URL.String(), request.URL.RequestURI()}
	if request.Method == base.Setup {
		if base := trackBase(request.URL); base != nil {
			candidates = append(candidates, base.String(), base.RequestURI())
		}
	}
	trimmed := strings.TrimSuffix(received, "/")
	for _, candidate := range candidates {
		if received == candidate || trimmed == strings.TrimSuffix(candidate, "/") {
			return true
		}
	}
	return false
}

// trackBase removes the last path segment of a SETUP track URL.
func trackBase(u *base.URL) *base.URL {
	path := strings.TrimSuffix(u.Path, "/")
	index := strings.LastIndexByte(path, '/')
	if index <= 0 {
		return nil
	}
	result := u.Clone()
	result.Path = path[:index+1]
	result.RawPath = ""
	return result
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// logAuthorizationFailure records only fixed labels and negotiation flags.
// Rejected requests and Digest URIs can contain arbitrary client-supplied data.
// Missing credentials are the ordinary challenge and stay at debug level.
func (s *Server) logAuthorizationFailure(request *base.Request, reason string) {
	fields := []any{"method", fixedRTSPMethod(request.Method), "profile", fixedRTSPProfile(request.URL), "reason", reason}
	if reason == "no_credentials" {
		s.logger.Debug("camera RTSP authorization challenge", fields...)
		return
	}
	var credentials headers.Authorization
	if credentials.Unmarshal(request.Header["Authorization"]) == nil {
		fields = append(fields, "qop", credentials.Qop != nil)
	}
	s.logger.Info("camera RTSP authorization rejected", fields...)
}

func fixedRTSPMethod(method base.Method) string {
	switch method {
	case base.Options, base.Describe, base.Setup, base.Play, base.Pause, base.Teardown, base.GetParameter:
		return string(method)
	default:
		return "other"
	}
}

func fixedRTSPProfile(target *base.URL) string {
	if target != nil {
		for _, profile := range []string{"stream1", "stream2"} {
			if target.Path == "/"+profile || strings.HasPrefix(target.Path, "/"+profile+"/") {
				return profile
			}
		}
	}
	return "other"
}
