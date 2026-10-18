package camerartsp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/auth"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
)

// ProfileStatus contains only operational data, never source URLs or secrets.
type ProfileStatus struct {
	State         string    `json:"state"`
	Reason        string    `json:"reason,omitempty"`
	Attempts      uint64    `json:"attempts"`
	Packets       uint64    `json:"packets"`
	NextRetryUTC  time.Time `json:"next_retry_utc,omitempty"`
	LastPacketUTC time.Time `json:"last_packet_utc,omitempty"`
}

// Status distinguishes a listening proxy from actual upstream media readiness.
type Status struct {
	Listening  bool                     `json:"listening"`
	AuthFailed bool                     `json:"authentication_failed"`
	Clients    int64                    `json:"clients"`
	Sessions   int                      `json:"sessions"`
	Profiles   map[string]ProfileStatus `json:"profiles"`
}

type profile struct {
	name, url  string
	status     ProfileStatus
	stream     *gortsplib.ServerStream
	video      VideoMetadata
	packets    atomic.Uint64
	lastPacket atomic.Int64
}

// Server owns two independent shared upstream workers and a bounded TCP RTSP
// listener. An authentication rejection latches both workers until restart.
type Server struct {
	cfg    Config
	logger *slog.Logger
	// mu protects lifecycle, profiles and sessions. Network I/O is outside mu.
	mu                                     sync.Mutex
	started, closed, listening, authFailed bool
	address                                string
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	stopParent                             func() bool
	server                                 *gortsplib.Server
	listener                               *limitedListener
	profiles                               map[string]*profile
	sessions                               map[*gortsplib.ServerSession]bool
	requests                               map[*gortsplib.ServerConn]requestObservation
	connRequests                           map[*gortsplib.ServerConn]int
	nonces                                 map[*gortsplib.ServerConn]string
	wg                                     sync.WaitGroup
	closeOnce                              sync.Once
}

// New validates configuration without opening listeners or contacting devices.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger, address: cfg.Address, profiles: map[string]*profile{
		"/stream1": {name: "stream1", url: cfg.MainURL, status: ProfileStatus{State: "idle"}},
		"/stream2": {name: "stream2", url: cfg.SubURL, status: ProfileStatus{State: "idle"}},
	}, sessions: make(map[*gortsplib.ServerSession]bool)}, nil
}

// Start binds the listener and starts eager shared upstream workers. Successful
// return means listening, not media ready; Status reports each profile separately.
// A Server cannot be restarted. Cancellation closes the listener and all media.
func (s *Server) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return errors.New("RTSP proxy already started or closed")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(parent)
	allowed := make(map[netip.Addr]bool)
	for _, value := range s.cfg.AllowedClientIPs {
		ip, _ := netip.ParseAddr(value)
		allowed[ip.Unmap()] = true
	}
	s.server = &gortsplib.Server{RTSPAddress: s.cfg.Address, Handler: s,
		AuthMethods: []auth.VerifyMethod{auth.VerifyMethodDigestMD5},
		ReadTimeout: s.cfg.ReadTimeout, WriteTimeout: 5 * time.Second, WriteQueueSize: 1024,
		Listen: func(network, address string) (net.Listener, error) {
			listener, err := net.Listen(network, address)
			if err != nil {
				return nil, errors.New("bind RTSP proxy listener failed")
			}
			s.listener = &limitedListener{Listener: listener, allowed: allowed, limit: int64(s.cfg.MaxClients)}
			return s.listener, nil
		},
	}
	if err := s.server.Start(); err != nil {
		s.cancel()
		s.server = nil
		return errors.New("start RTSP proxy listener failed")
	}
	s.address = s.server.NetListener().Addr().String()
	s.listening = true
	for _, path := range []string{"/stream1", "/stream2"} {
		p := s.profiles[path]
		s.wg.Go(func() { s.runProfile(p) })
	}
	s.stopParent = context.AfterFunc(parent, s.Close)
	return nil
}

// Addr returns the actual bound listener address, including an allocated port.
func (s *Server) Addr() string { s.mu.Lock(); defer s.mu.Unlock(); return s.address }

// Status returns a credential-free, independent snapshot.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := Status{Listening: s.listening, AuthFailed: s.authFailed, Sessions: len(s.sessions), Profiles: make(map[string]ProfileStatus)}
	if s.listener != nil {
		result.Clients = s.listener.count.Load()
	}
	for _, p := range s.profiles {
		status := p.status
		status.Packets = p.packets.Load()
		if last := p.lastPacket.Load(); last != 0 {
			status.LastPacketUTC = time.Unix(0, last).UTC()
		}
		result.Profiles[p.name] = status
	}
	return result
}

// Close cancels workers and joins their cleanup; repeated/concurrent calls are safe.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.listening = false
		cancel, server, stop := s.cancel, s.server, s.stopParent
		s.mu.Unlock()
		if stop != nil {
			stop()
		}
		if cancel != nil {
			cancel()
		}
		if server != nil {
			server.Close()
		}
		s.wg.Wait()
	})
}

func (s *Server) selected(path, query string) (*gortsplib.ServerStream, base.StatusCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.profiles[path]
	if query != "" || p == nil {
		return nil, base.StatusNotFound
	}
	if s.closed || s.authFailed || p.stream == nil {
		return nil, base.StatusServiceUnavailable
	}
	return p.stream, base.StatusOK
}

// OnDescribe exposes only the two selected live profiles.
func (s *Server) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx) (*base.Response, *gortsplib.ServerStream, error) {
	if response := s.authorize(ctx.Conn, ctx.Request); response != nil {
		return response, nil, nil
	}
	stream, code := s.selected(ctx.Path, ctx.Query)
	return &base.Response{StatusCode: code}, stream, nil
}

// OnSetup permits RTP over TCP only and rejects sessions above the configured cap.
func (s *Server) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	if response := s.authorize(ctx.Conn, ctx.Request); response != nil {
		return response, nil, nil
	}
	s.mu.Lock()
	allowed := s.sessions[ctx.Session]
	s.mu.Unlock()
	if !allowed {
		return &base.Response{StatusCode: base.StatusServiceUnavailable}, nil, nil
	}
	if ctx.Transport == nil || ctx.Transport.Protocol != gortsplib.ProtocolTCP {
		return &base.Response{StatusCode: base.StatusUnsupportedTransport}, nil, nil
	}
	stream, code := s.selected(ctx.Path, ctx.Query)
	return &base.Response{StatusCode: code}, stream, nil
}

// OnPlay does not restart the shared upstream for another viewer.
func (s *Server) OnPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	if response := s.authorize(ctx.Conn, ctx.Request); response != nil {
		return response, nil
	}
	_, code := s.selected(ctx.Path, ctx.Query)
	return &base.Response{StatusCode: code}, nil
}

// OnSessionOpen bounds sessions even if one TCP client creates several.
func (s *Server) OnSessionOpen(ctx *gortsplib.ServerHandlerOnSessionOpenCtx) {
	s.mu.Lock()
	allowed := !s.closed && len(s.sessions) < s.cfg.MaxClients
	if allowed {
		s.sessions[ctx.Session] = true
	}
	s.mu.Unlock()
	if !allowed {
		ctx.Session.Close()
	}
}

// OnSessionClose releases a reader slot.
func (s *Server) OnSessionClose(ctx *gortsplib.ServerHandlerOnSessionCloseCtx) {
	s.mu.Lock()
	delete(s.sessions, ctx.Session)
	s.mu.Unlock()
}

// OnStreamWriteError disconnects only the slow/failed reader.
func (s *Server) OnStreamWriteError(ctx *gortsplib.ServerHandlerOnStreamWriteErrorCtx) {
	ctx.Session.Close()
}

type limitedListener struct {
	net.Listener
	allowed map[netip.Addr]bool
	limit   int64
	count   atomic.Int64
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if len(l.allowed) != 0 {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip, _ := netip.ParseAddr(host)
			if !ip.IsValid() || !l.allowed[ip.Unmap()] {
				_ = conn.Close()
				continue
			}
		}
		if l.count.Add(1) > l.limit {
			l.count.Add(-1)
			_ = conn.Close()
			continue
		}
		return &countedConn{Conn: conn, release: func() { l.count.Add(-1) }}, nil
	}
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
