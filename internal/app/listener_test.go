package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagementHTTPSAcceptsAnyPeerWithoutAllowlist(t *testing.T) {
	for _, peers := range [][]string{nil, {}} {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		s.Listener = restrict(&managementPeerListener{Listener: s.Listener, conn: serverConn}, peers)
		s.StartTLS()
		t.Cleanup(s.Close)
		client := s.Client()
		client.Timeout = time.Second
		client.Transport.(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		}
		response, err := client.Get(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("unlisted peer could not complete an HTTPS request")
		}
	}
}

func TestUnrestrictedManagementRetainsConnectionLimit(t *testing.T) {
	queue := &managementConnectionQueue{}
	listener := restrict(queue, nil).(*restrictedListener)
	var clients []net.Conn
	add := func() {
		server, client := net.Pipe()
		queue.connections = append(queue.connections, &managementPeerConn{Conn: server})
		clients = append(clients, client)
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	}
	var accepted []net.Conn
	for range 16 {
		add()
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, conn)
		t.Cleanup(func() { _ = conn.Close() })
	}
	add()
	if _, err := listener.Accept(); err != net.ErrClosed {
		t.Fatal("management listener exceeded its 16-connection cap")
	}
	_ = clients[16].SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := clients[16].Read(data[:]); err != io.EOF {
		t.Fatalf("excess connection was not closed: %v", err)
	}
	_ = accepted[0].Close()
	_ = accepted[0].Close()
	add()
	replacement, err := listener.Accept()
	if err != nil || len(listener.slots) != 16 {
		t.Fatal("closing a connection did not release exactly one slot")
	}
	_ = replacement.Close()
	for _, conn := range accepted {
		_ = conn.Close()
	}
	if len(listener.slots) != 0 {
		t.Fatal("management connection slots leaked")
	}
}

// managementPeerConn gives local pipe connections a fixed nonloopback identity for admission
// tests.
type managementPeerConn struct{ net.Conn }

// RemoteAddr reports the fixture peer used to test exact management allowlists.
func (*managementPeerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 1234}
}

// managementPeerListener supplies an initial pipe then decorates later accepted connections
// with the fixture peer identity.
type managementPeerListener struct {
	net.Listener
	conn net.Conn
}

// Accept returns the pending pipe first, then wraps connections from the underlying test
// listener.
func (l *managementPeerListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		return &managementPeerConn{Conn: conn}, nil
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &managementPeerConn{Conn: conn}, nil
}

// managementConnectionQueue provides a finite sequence of connections for exercising
// listener slot limits.
type managementConnectionQueue struct {
	net.Listener
	connections []net.Conn
}

// Accept pops one prepared connection or reports closure when the fixture queue is empty.
func (l *managementConnectionQueue) Accept() (net.Conn, error) {
	if len(l.connections) == 0 {
		return nil, net.ErrClosed
	}
	conn := l.connections[0]
	l.connections = l.connections[1:]
	return conn, nil
}
