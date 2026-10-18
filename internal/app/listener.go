package app

import (
	"net"
	"net/netip"
	"sync"
)

// restrictedListener bounds connections before TLS parsing and optionally checks
// transport identity. An empty peer set accepts clients from any source IP.
type restrictedListener struct {
	net.Listener
	peers map[netip.Addr]bool
	slots chan struct{}
}

// restrict wraps a listener with a 16-connection limit and optional exact peer addresses
// from validated configuration.
func restrict(listener net.Listener, peers []string) net.Listener {
	allowed := map[netip.Addr]bool{}
	for _, value := range peers {
		ip, _ := netip.ParseAddr(value)
		allowed[ip.Unmap()] = true
	}
	return &restrictedListener{Listener: listener, peers: allowed, slots: make(chan struct{}, 16)}
}

// Accept closes disallowed or excess connections before TLS handling and returns an admitted
// connection with one reserved slot.
func (l *restrictedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if len(l.peers) != 0 {
			host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			ip, ipErr := netip.ParseAddr(host)
			if err != nil || ipErr != nil || !l.peers[ip.Unmap()] {
				_ = conn.Close()
				continue
			}
		}
		select {
		case l.slots <- struct{}{}:
			return &countedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

// countedConn releases one admission slot exactly once even if several owners close the same
// connection.
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close closes the transport and releases its connection slot once, preserving the
// underlying close error.
func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
