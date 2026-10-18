package camerartsp

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/liberrors"
)

// requestObservation retains the bounded request metadata needed when the
// corresponding response is logged and its transport header is negotiated.
type requestObservation struct {
	method, profile  string
	nativeEncryption bool
}

// OnRequest retains only fixed labels and negotiation flags, never credentials,
// session IDs, URLs or arbitrary client headers.
func (s *Server) OnRequest(connection *gortsplib.ServerConn, request *base.Request) {
	observation := requestObservation{method: "other", profile: "other"}
	switch request.Method {
	case base.Options, base.Describe, base.Setup, base.Play, base.Pause, base.Teardown, base.GetParameter:
		observation.method = string(request.Method)
	}
	if request.URL != nil {
		for _, profile := range []string{"stream1", "stream2"} {
			if request.URL.Path == "/"+profile || strings.HasPrefix(request.URL.Path, "/"+profile+"/") {
				observation.profile = profile
			}
		}
	}
	for _, value := range request.Header["Transport"] {
		for _, part := range strings.Split(value, ";") {
			key, value, present := strings.Cut(strings.TrimSpace(part), "=")
			if present && key == "encrypt" && (value == "0" || value == "1") {
				observation.nativeEncryption = true
			}
		}
	}
	s.mu.Lock()
	if s.requests == nil {
		s.requests = make(map[*gortsplib.ServerConn]requestObservation)
	}
	s.requests[connection] = observation
	if s.connRequests != nil {
		s.connRequests[connection]++
	}
	s.mu.Unlock()
}

// OnConnOpen records every accepted RTSP TCP connection, so a recorder that
// connects but never completes a request is still visible. Only the peer IP is
// logged; behind a NAT alias this is the forwarding router, not the recorder.
func (s *Server) OnConnOpen(ctx *gortsplib.ServerHandlerOnConnOpenCtx) {
	s.mu.Lock()
	if s.connRequests == nil {
		s.connRequests = make(map[*gortsplib.ServerConn]int)
	}
	s.connRequests[ctx.Conn] = 0
	s.mu.Unlock()
	s.logger.Info("camera RTSP connection opened", "peer_ip", peerIP(ctx.Conn))
}

// peerIP extracts a connection's remote host for logs, returning "unknown"
// when the connection has no usable network address.
func peerIP(connection *gortsplib.ServerConn) string {
	if connection == nil || connection.NetConn() == nil || connection.NetConn().RemoteAddr() == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(connection.NetConn().RemoteAddr().String())
	if err != nil {
		return "unknown"
	}
	return host
}

// closeReason maps a connection error to a fixed label without client data.
func closeReason(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, liberrors.ErrServerTerminated{}):
		return "server_closed"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

// OnResponse runs after gortsplib builds Transport. The captured Omada camera
// explicitly selects encrypt=0 for ordinary video/audio; our RTP is unencrypted.
func (s *Server) OnResponse(connection *gortsplib.ServerConn, response *base.Response) {
	s.mu.Lock()
	observation, present := s.requests[connection]
	delete(s.requests, connection)
	s.mu.Unlock()
	if !present {
		return
	}
	if observation.method == string(base.Setup) && observation.nativeEncryption && response.StatusCode == base.StatusOK {
		if values := response.Header["Transport"]; len(values) == 1 && strings.HasPrefix(values[0], "RTP/AVP/TCP;") {
			response.Header["Transport"] = base.HeaderValue{values[0] + ";encrypt=0"}
		}
	}
	s.logger.Info("camera RTSP request", "method", observation.method, "profile", observation.profile,
		"status", int(response.StatusCode), "native_encryption_negotiation", observation.nativeEncryption)
}

// OnConnClose also drops observations for connections interrupted before a reply.
func (s *Server) OnConnClose(context *gortsplib.ServerHandlerOnConnCloseCtx) {
	s.mu.Lock()
	delete(s.requests, context.Conn)
	delete(s.nonces, context.Conn)
	requests, tracked := s.connRequests[context.Conn]
	delete(s.connRequests, context.Conn)
	s.mu.Unlock()
	if tracked {
		s.logger.Info("camera RTSP connection closed", "peer_ip", peerIP(context.Conn), "requests", requests, "close_reason", closeReason(context.Error))
	}
}
