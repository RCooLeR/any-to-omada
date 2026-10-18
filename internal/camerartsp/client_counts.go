package camerartsp

import (
	"net"
	"net/netip"

	"github.com/bluenviron/gortsplib/v5"
)

// ClientCounts reports downstream PLAY sessions and their distinct peer IPs.
// Eager source readers are deliberately excluded from native camera discovery.
func (s *Server) ClientCounts() (streams, ips int) {
	s.mu.Lock()
	sessions := make([]*gortsplib.ServerSession, 0, len(s.sessions))
	for session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()
	peers := make(map[netip.Addr]struct{})
	for _, session := range sessions {
		if session.State() != gortsplib.ServerSessionStatePlay {
			continue
		}
		streams++
		for _, conn := range session.Conns() {
			host, _, err := net.SplitHostPort(conn.NetConn().RemoteAddr().String())
			if err != nil {
				continue
			}
			if address, err := netip.ParseAddr(host); err == nil {
				peers[address.Unmap()] = struct{}{}
			}
		}
	}
	return streams, len(peers)
}
