package omadalink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/spakeee"
)

type syntheticPAKE struct {
	keys      spakeee.Keys
	finishErr error
	destroyed bool
}

func (p *syntheticPAKE) Finish(response []byte, clientID, serverID string) ([]byte, spakeee.Keys, error) {
	if len(response) != 64 || clientID != "VIGI-IPC" || serverID != "VIGI-NVR" {
		return nil, spakeee.Keys{}, errors.New("unexpected test exchange")
	}
	return bytes.Repeat([]byte{6}, 32), p.keys, p.finishErr
}

func (p *syntheticPAKE) Destroy() { p.destroyed = true }

type deadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

type readStartedConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *readStartedConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(data)
}

func (c *deadlineConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func TestCameraVersionReplyMatchesCapturedWireForm(t *testing.T) {
	// The algorithm identifier is public protocol metadata, not captured PAKE data.
	const expected = "--start-boundary--\r\nContent-Type:ALG_Ver\r\nContent-Length:39\r\n{\"step\":2,\"data\":\"MS4w\",\"error_code\":0}\r\n--end-boundary--"
	var output bytes.Buffer
	if err := writeHandshakeMessage(&output, AlgorithmVersion, 2, []byte("1.0")); err != nil {
		t.Fatal(err)
	}
	if output.String() != expected || output.Len() != 118 {
		t.Fatal("camera version reply differs from the observed field order, header spacing or ending")
	}
}

func TestHandshakeSyntheticTLSUpgrade(t *testing.T) {
	for _, wrongCertificate := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong-certificate=%v", wrongCertificate), func(t *testing.T) {
			certificate, certificatePEM := syntheticCertificate(t, nil, nil, false)
			if wrongCertificate {
				_, certificatePEM = syntheticCertificate(t, nil, nil, false)
			}
			keys := syntheticKeys()
			client, server := net.Pipe()
			defer server.Close()
			tracked := &deadlineConn{Conn: client}
			serverDone := make(chan error, 1)
			go func() {
				_ = server.SetDeadline(time.Now().Add(4 * time.Second))
				reader := bufio.NewReader(server)
				if err := syntheticServerExchange(reader, server, encryptedPEM(certificatePEM, keys)); err != nil {
					serverDone <- err
					return
				}
				secured := tls.Server(&bufferedConn{Conn: server, reader: reader}, &tls.Config{
					Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{tls.CurveP521},
				})
				if err := secured.Handshake(); err != nil {
					serverDone <- err
					return
				}
				var received [4]byte
				if _, err := io.ReadFull(secured, received[:]); err != nil || string(received[:]) != "ping" {
					serverDone <- errors.New("TLS application read failed")
					return
				}
				_, err := secured.Write([]byte("pong"))
				serverDone <- err
			}()
			pake := &syntheticPAKE{keys: keys}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secured, err := handshake(ctx, tracked, "synthetic-registration", func(data []byte, password string) (pakeClient, []byte, error) {
				if len(data) != 36 || password != "synthetic-registration" {
					return nil, nil, errors.New("unexpected factory input")
				}
				return pake, bytes.Repeat([]byte{4}, 32), nil
			})
			if !pake.destroyed {
				t.Error("PAKE state was not released")
			}
			if wrongCertificate {
				if secured != nil || !errors.Is(err, ErrHandshake) {
					t.Fatalf("wrong certificate accepted: %v", err)
				}
				diagnostics, ok := FailureDiagnostics(err)
				if !ok || diagnostics.Stage != "tls" || diagnostics.ReceivedBytes == 0 || diagnostics.SentBytes == 0 {
					t.Fatal("rejected TLS authentication lacked safe progress diagnostics")
				}
				if err := <-serverDone; err == nil {
					t.Fatal("server unexpectedly completed the rejected TLS exchange")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			tracked.mu.Lock()
			deadlineCleared := tracked.deadline.IsZero()
			tracked.mu.Unlock()
			if !deadlineCleared || secured.ConnectionState().Version != tls.VersionTLS12 {
				t.Fatal("TLS version or cleared transport deadline mismatch")
			}
			// The handshake's context no longer owns the established TLS connection.
			cancel()
			if _, err := secured.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var received [4]byte
			if _, err := io.ReadFull(secured, received[:]); err != nil || string(received[:]) != "pong" {
				t.Fatalf("TLS application exchange failed: %v", err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandshakeCancellationClosesBlockedConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	tracked := &readStartedConn{Conn: client, started: make(chan struct{})}
	go func() {
		_, err := Handshake(ctx, tracked, "synthetic-registration")
		done <- err
	}()
	select {
	case <-tracked.started:
	case <-time.After(time.Second):
		t.Fatal("handshake never entered the transport read")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrHandshake) {
			t.Fatalf("cancellation error = %v", err)
		}
		assertHandshakeDiagnostics(t, err, "read_version", 0, 0)
	case <-time.After(time.Second):
		t.Fatal("canceled handshake did not terminate")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed handshake did not close connection: %v", err)
	}
}

func TestHandshakeDeadlineInterruptsBlockedRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Handshake(ctx, client, "synthetic-registration")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("deadline error = %v", err)
	}
	assertHandshakeDiagnostics(t, err, "read_version", 0, 0)
}

func TestHandshakeRejectsInvalidRegistration(t *testing.T) {
	for _, value := range []string{"", "has a space", "line\nbreak", strings.Repeat("x", 65), "non-ascii-\u00e9"} {
		t.Run(fmt.Sprintf("length-%d", len(value)), func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			if _, err := Handshake(context.Background(), client, value); !errors.Is(err, ErrHandshake) || strings.Contains(err.Error(), value) && value != "" {
				t.Fatalf("invalid registration error was not redacted: %v", err)
			}
		})
	}
}

func TestHandshakeProofFailureDoesNotReadCertificate(t *testing.T) {
	var input, output bytes.Buffer
	for _, message := range []struct{ step, size int }{{1, 3}, {3, 36}, {5, 64}} {
		data := make([]byte, message.size)
		contentType := Spake2
		if message.step == 1 {
			data, contentType = []byte("1.0"), AlgorithmVersion
		}
		if err := writeSyntheticServerFrame(&input, contentType, message.step, data); err != nil {
			t.Fatal(err)
		}
	}
	pake := &syntheticPAKE{finishErr: errors.New("synthetic private proof failure")}
	_, err := exchangeHandshake(context.Background(), bufio.NewReader(&input), &output, "synthetic-registration", func([]byte, string) (pakeClient, []byte, error) {
		return pake, make([]byte, 32), nil
	}, &handshakeProgress{})
	if !errors.Is(err, ErrHandshake) || strings.Contains(err.Error(), "private") || !pake.destroyed {
		t.Fatalf("proof error/state handling = %v", err)
	}
	reader := bufio.NewReader(&output)
	for _, step := range []int{2, 4} {
		frame, err := ReadFrame(reader, false)
		var message handshakeMessage
		if err != nil || json.Unmarshal(frame.Body, &message) != nil || message.Step == nil || *message.Step != step {
			t.Fatalf("unexpected output before rejected proof: %v", err)
		}
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatal("confirmation was sent after rejected proof")
	}
}

func TestReadHandshakeMessageRejectsInvalidStep(t *testing.T) {
	for _, body := range []string{
		`{"step":1,"data":"MS4w"}`,
		`{"step":1,"error_code":-1,"data":"MS4w"}`,
		`{"step":2,"error_code":0,"data":"MS4w"}`,
		`{"step":1,"error_code":0,"data":"!!private!!"}`,
		`{"step":1,"error_code":0,"data":"eA=="}`,
	} {
		encoded, err := Encode(Frame{ContentType: AlgorithmVersion, Body: json.RawMessage(body)}, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = readHandshakeMessage(bufio.NewReader(bytes.NewReader(encoded)), AlgorithmVersion, 1, 3, 3)
		if !errors.Is(err, ErrHandshake) || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid step error = %v", err)
		}
	}
}

func TestCertificatePaddingAndCBC(t *testing.T) {
	_, certificatePEM := syntheticCertificate(t, nil, nil, false)
	keys := syntheticKeys()
	certificates, err := decryptCertificates(encryptedPEM(certificatePEM, keys), keys)
	if err != nil || len(certificates) != 1 {
		t.Fatalf("CBC certificate decode = %v", err)
	}
	for padding := 1; padding <= aes.BlockSize; padding++ {
		plain := append(bytes.Clone(certificatePEM), bytes.Repeat([]byte{byte(padding)}, padding)...)
		if _, err := parseCertificates(plain); err != nil {
			t.Fatalf("PKCS#7 padding %d rejected: %v", padding, err)
		}
		plain = append(bytes.Clone(certificatePEM), make([]byte, padding)...)
		if _, err := parseCertificates(plain); err != nil {
			t.Fatalf("zero padding %d rejected: %v", padding, err)
		}
	}
	for _, suffix := range [][]byte{
		{2, 3}, {9, 9, 10}, {10, 9, 9}, {13, 13, 10}, {0, 1}, make([]byte, 17), []byte("unexpected"),
	} {
		if _, err := parseCertificates(append(bytes.Clone(certificatePEM), suffix...)); !errors.Is(err, ErrHandshake) {
			t.Fatalf("malformed padding accepted (length %d)", len(suffix))
		}
	}
	for _, encrypted := range [][]byte{nil, make([]byte, 15), make([]byte, maxCertificateBytes+16)} {
		if _, err := decryptCertificates(encrypted, keys); !errors.Is(err, ErrHandshake) {
			t.Fatal("invalid CBC size accepted")
		}
	}
	if _, err := parseCertificates(bytes.Repeat(certificatePEM, maxTrustedCertificates+1)); !errors.Is(err, ErrHandshake) {
		t.Fatal("oversized certificate chain accepted")
	}
}

func TestRecorderTrustBinding(t *testing.T) {
	root, rootPEM := syntheticCertificate(t, nil, nil, true)
	rootCertificate := root.Leaf
	leaf, _ := syntheticCertificate(t, rootCertificate, root.PrivateKey, false)
	wrong, _ := syntheticCertificate(t, nil, nil, true)
	trusted, err := parseCertificates(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	// All generated dates are in the past and the DNS name is deliberately not
	// the connection target. Only those compatibility exceptions are permitted.
	if err := verifyRecorderCertificate([]*x509.Certificate{leaf.Leaf}, trusted); err != nil {
		t.Fatalf("authenticated CA chain rejected: %v", err)
	}
	if err := verifyRecorderCertificate([]*x509.Certificate{leaf.Leaf}, []*x509.Certificate{leaf.Leaf}); err != nil {
		t.Fatalf("authenticated leaf rejected: %v", err)
	}
	for _, peers := range [][]*x509.Certificate{nil, {nil}, {wrong.Leaf}} {
		if err := verifyRecorderCertificate(peers, trusted); !errors.Is(err, ErrPeerCertificate) {
			t.Fatal("untrusted peer accepted")
		}
	}
	if err := verifyRecorderCertificate([]*x509.Certificate{leaf.Leaf}, []*x509.Certificate{wrong.Leaf}); !errors.Is(err, ErrPeerCertificate) {
		t.Fatal("unrelated CA accepted")
	}
}

func TestBufferedTLSBytesPreserved(t *testing.T) {
	var input bytes.Buffer
	if err := writeSyntheticServerFrame(&input, Spake2, 7, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	following := []byte{0x16, 3, 3, 0, 4, 1, 2, 3, 4}
	input.Write(following)
	reader := bufio.NewReader(&input)
	if _, err := readHandshakeMessage(reader, Spake2, 7, 16, 16); err != nil {
		t.Fatal(err)
	}
	if reader.Buffered() != len(following) {
		t.Fatal("test did not exercise buffered bytes")
	}
	connection := &bufferedConn{reader: reader}
	actual, err := io.ReadAll(connection)
	if err != nil || !bytes.Equal(actual, following) {
		t.Fatalf("following TLS bytes lost: %v", err)
	}
}

func syntheticKeys() spakeee.Keys {
	var keys spakeee.Keys
	for i := range keys.Client {
		keys.Client[i], keys.Server[i] = byte(i+1), byte(i+65)
	}
	return keys
}

func encryptedPEM(data []byte, keys spakeee.Keys) []byte {
	key := append(bytes.Clone(keys.Server[:8]), keys.Client[8:16]...)
	iv := append(bytes.Clone(keys.Client[:8]), keys.Server[8:16]...)
	block, _ := aes.NewCipher(key)
	padding := aes.BlockSize - len(data)%aes.BlockSize
	plain := append(bytes.Clone(data), bytes.Repeat([]byte{byte(padding)}, padding)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	return encrypted
}

func syntheticCertificate(t *testing.T, parent *x509.Certificate, parentKey any, isCA bool) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic.example.invalid"},
		NotBefore: time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames: []string{"synthetic.example.invalid"}, BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func syntheticServerExchange(reader *bufio.Reader, writer io.Writer, encrypted []byte) error {
	for _, message := range []struct {
		step int
		data []byte
	}{{1, []byte("1.0")}, {3, make([]byte, 36)}, {5, make([]byte, 64)}, {7, encrypted}} {
		contentType := Spake2
		if message.step == 1 {
			contentType = AlgorithmVersion
		}
		if err := writeSyntheticServerFrame(writer, contentType, message.step, message.data); err != nil {
			return err
		}
		if message.step == 7 {
			return nil
		}
		frame, err := ReadFrame(reader, false)
		var response handshakeMessage
		if err != nil || json.Unmarshal(frame.Body, &response) != nil || response.Step == nil || *response.Step != message.step+1 {
			return errors.New("synthetic peer received an invalid response")
		}
	}
	return nil
}

func writeSyntheticServerFrame(writer io.Writer, contentType ContentType, step int, data []byte) error {
	zero := 0
	body, err := json.Marshal(handshakeMessage{Step: &step, ErrorCode: &zero, Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return err
	}
	encoded, err := Encode(Frame{ContentType: contentType, Body: body}, true)
	if err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}
