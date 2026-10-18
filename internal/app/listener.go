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

func restrict(listener net.Listener, peers []string) net.Listener {
	allowed := map[netip.Addr]bool{}
	for _, value := range peers {
		ip, _ := netip.ParseAddr(value)
		allowed[ip.Unmap()] = true
	}
	return &restrictedListener{Listener: listener, peers: allowed, slots: make(chan struct{}, 16)}
}

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

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
