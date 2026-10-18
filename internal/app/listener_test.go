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

type managementPeerConn struct{ net.Conn }

func (*managementPeerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 1234}
}

type managementPeerListener struct {
	net.Listener
	conn net.Conn
}

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

type managementConnectionQueue struct {
	net.Listener
	connections []net.Conn
}

func (l *managementConnectionQueue) Accept() (net.Conn, error) {
	if len(l.connections) == 0 {
		return nil, net.ErrClosed
	}
	conn := l.connections[0]
	l.connections = l.connections[1:]
	return conn, nil
}
