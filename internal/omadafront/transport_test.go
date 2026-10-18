package omadafront

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeHTTP11UsesChunkedResponseAndClosesConnection(t *testing.T) {
	var callbackCalls atomic.Int32
	handler := testServer(t, func(c *Config) {
		c.StartCallback = func(CallbackRequest) error { callbackCalls.Add(1); return nil }
	})
	server, listener := memoryTLSServer(t, handler)
	defer server.Close()
	callbackBody := `{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"192.0.2.150","port":6000,"version":"0101000101","auth_code":"synthetic-registration"}}}`
	sessionPath := ""
	for _, test := range []struct {
		name        string
		path        string
		body        string
		status      int
		errorCode   float64
		usesSession bool
	}{
		{"discovery", "/stok=/ds", "{\n\t\"method\": \"do\",\n\t\"get_rtsp_info\": {\n\t}\n}", http.StatusOK, 0, false},
		{"anonymous callback challenge", "/stok=/ds", callbackBody, http.StatusUnauthorized, unauthorizedCode, false},
		{"explicit authentication challenge", "/stok=/ds", `{"method":"do","user_management":{"get_encrypt_info":null}}`, http.StatusUnauthorized, unauthorizedCode, false},
		{"login", "/", `{"method":"do","login":{"username":"fixture-operator","password":"48A884BED8D6C46E9DC303655C804B0A","passwdType":"md5"}}`, http.StatusOK, 0, false},
		{"authenticated callback", "", callbackBody, http.StatusOK, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := test.path
			if test.usesSession {
				if sessionPath == "" {
					t.Fatal("preceding login did not establish a session")
				}
				path = sessionPath
			}
			wire := rawTLSRequest(t, server, listener, "HTTP/1.1", path, test.body)
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal("response was not valid HTTP")
			}
			defer response.Body.Close()
			if response.StatusCode != test.status || response.Proto != "HTTP/1.1" || !response.Close {
				t.Fatalf("response status/protocol/close mismatch: status=%d close=%v", response.StatusCode, response.Close)
			}
			if response.Header.Get("Content-Length") != "" || response.ContentLength != -1 || len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" {
				t.Fatal("response did not use only chunked framing")
			}
			if response.Header.Get("Content-Type") != "application/json" || !bytes.HasSuffix(wire, []byte("\r\n0\r\n\r\n")) {
				t.Fatal("JSON response or final chunk terminator missing")
			}
			body, err := io.ReadAll(response.Body)
			var value map[string]any
			if err != nil || json.Unmarshal(body, &value) != nil || value["error_code"] != test.errorCode {
				t.Fatal("response body was incomplete or had an unexpected result")
			}
			if test.name == "login" {
				token, ok := value["stok"].(string)
				if !ok || len(token) != 2*sessionBytes {
					t.Fatal("login did not return a valid local session")
				}
				sessionPath = "/stok=" + token + "/ds"
			}
			if test.usesSession && value["version"] != "0101000101" {
				t.Fatal("callback registration version mismatch")
			}
		})
	}
	if callbackCalls.Load() != 1 {
		t.Fatal("only the authenticated callback may start a worker")
	}
}

func TestNativeHTTP10DoesNotAdvertiseChunkedEncoding(t *testing.T) {
	server, listener := memoryTLSServer(t, testServer(t, nil))
	defer server.Close()
	wire := rawTLSRequest(t, server, listener, "HTTP/1.0", "/stok=/ds", `{"method":"do","get_rtsp_info":{}}`)
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.TransferEncoding) != 0 || response.Header.Get("Transfer-Encoding") != "" {
		t.Fatal("HTTP/1.0 response used unsupported chunk framing")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal("HTTP/1.0 response body was incomplete")
	}
}

func rawTLSRequest(t *testing.T, server *httptest.Server, listener *memoryHTTPListener, protocol, path, body string) []byte {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, peer := net.Pipe()
	defer peer.Close()
	select {
	case listener.connections <- peer:
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("synthetic HTTP server did not accept the connection")
	}
	connection := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := connection.Handshake(); err != nil {
		t.Fatalf("could not authenticate the synthetic TLS server: %v", err)
	}
	connectionHeader := "close"
	if protocol == "HTTP/1.1" {
		connectionHeader = "keep-alive"
	}
	// Captured native requests include an extra CRLF outside Content-Length.
	// Response completion must not wait for another request on that connection.
	request := fmt.Sprintf("POST %s %s\r\nHost: synthetic.example.invalid\r\nConnection: %s\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s\r\n", path, protocol, connectionHeader, len(body), body)
	if _, err := io.Copy(connection, strings.NewReader(request)); err != nil {
		t.Fatal("could not write the synthetic HTTP request")
	}
	wire, err := io.ReadAll(io.LimitReader(connection, 128*1024))
	if err != nil {
		t.Fatal("response did not finish with connection EOF before its deadline")
	}
	if len(wire) == 128*1024 {
		t.Fatal("response exceeded the test's bounded read")
	}
	return wire
}

// Keep real net/http and TLS framing while preventing workstation HTTPS
// inspection software from substituting a certificate on loopback sockets.
func memoryTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *memoryHTTPListener) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener := &memoryHTTPListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	server.Listener = listener
	server.StartTLS()
	return server, listener
}

// memoryHTTPListener supplies in-memory connections to httptest and unblocks
// acceptors when closed, without opening a real listener.
type memoryHTTPListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

// Accept waits for a supplied connection or reports a closed listener.
func (l *memoryHTTPListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close releases blocked accepts exactly once and is safe to repeat.
func (l *memoryHTTPListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr supplies the loopback address required by the listener interface;
// it does not describe a real bound TCP socket.
func (l *memoryHTTPListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
