package omadalink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/spakeee"
)

const (
	handshakeTimeout       = 15 * time.Second
	maxCertificateBytes    = 10 * 1024
	maxTrustedCertificates = 8
)

var (
	ErrHandshake       = errors.New("omada callback handshake failed")
	ErrPeerCertificate = errors.New("recorder certificate does not match callback trust")
)

// handshakeMessage represents a pre-TLS step; pointer fields distinguish
// missing step/error fields from explicit zero values.
type handshakeMessage struct {
	Step      *int   `json:"step"`
	Data      string `json:"data"`
	ErrorCode *int   `json:"error_code"`
}

type pakeClient interface {
	// Finish verifies the recorder proof and consumes the exchange state.
	Finish([]byte, string, string) ([]byte, spakeee.Keys, error)
	// Destroy releases retained exchange state after completion or abort.
	Destroy()
}

type pakeFactory func([]byte, string) (pakeClient, []byte, error)

// Handshake performs the camera side of the native recorder callback and TLS 1.2
// upgrade. authCode must come from this registration's nvr_connect_start request;
// it is not the camera account password and must never be logged or persisted.
// The function owns conn: failures close it, and success returns its TLS wrapper.
// Callers must not read conn concurrently or impose their own handshake deadline.
func Handshake(ctx context.Context, conn net.Conn, authCode string) (*tls.Conn, error) {
	return handshake(ctx, conn, authCode, func(data []byte, password string) (pakeClient, []byte, error) {
		return spakeee.NewClient(data, password)
	})
}

// handshake owns the connection through PAKE and TLS, clearing its temporary
// deadline on success and closing it on failure; factory supplies the PAKE engine.
func handshake(ctx context.Context, conn net.Conn, authCode string, factory pakeFactory) (_ *tls.Conn, err error) {
	progress := &handshakeProgress{stage: stageValidateRegistration, details: HandshakeDiagnostics{Reason: "stage_failed", PrefixCategory: "not_read", OfferVersion: "not_read"}}
	defer func() {
		if err != nil {
			err = &handshakeFailure{diagnostics: progress.snapshot(), cause: err}
		}
	}()
	if conn == nil {
		return nil, fmt.Errorf("%w: missing connection", ErrHandshake)
	}
	conn = &handshakeCountConn{Conn: conn, progress: progress}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	if ctx == nil || !validAuthCode(authCode) {
		return nil, fmt.Errorf("%w: invalid registration input", ErrHandshake)
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	progress.stage = stageSetDeadline
	progress.details.Reason = "set_deadline"
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: set deadline", ErrHandshake)
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(canceled)
	})
	callbackStopped := false
	stopCallback := func() {
		if !callbackStopped {
			callbackStopped = true
			if !stop() {
				<-canceled
			}
		}
	}
	defer func() {
		stopCallback()
		if err != nil {
			if contextError := ctx.Err(); contextError != nil {
				err = contextError
			} else if !time.Now().Before(deadline) {
				// A transport's deadline can wake its reader just before the
				// context timer publishes DeadlineExceeded.
				err = context.DeadlineExceeded
			}
		}
	}()
	reader := bufio.NewReader(conn)
	certificates, err := exchangeHandshake(ctx, reader, conn, authCode, factory, progress)
	if err != nil {
		return nil, err
	}
	progress.stage = stageTLS
	progress.details.Reason = "tls_authentication"
	secured := tls.Client(&bufferedConn{Conn: conn, reader: reader}, recorderTLSConfig(certificates))
	if err := secured.HandshakeContext(ctx); err != nil {
		progress.details.Reason = "tls_authentication"
		return nil, fmt.Errorf("%w: TLS authentication", ErrHandshake)
	}
	// Stop cancellation's deadline callback before clearing its deadline. Otherwise
	// it could race with a successful handshake and poison the returned connection.
	stopCallback()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	progress.stage = stageClearDeadline
	progress.details.Reason = "clear_deadline"
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear deadline", ErrHandshake)
	}
	return secured, nil
}

// exchangeHandshake executes the ordered native negotiation and PAKE exchange,
// then decrypts recorder certificates using the PAKE-derived keys after proof verification.
func exchangeHandshake(ctx context.Context, reader *bufio.Reader, writer io.Writer, authCode string, factory pakeFactory, progress *handshakeProgress) ([]*x509.Certificate, error) {
	progress.stage = stageReadVersion
	version, err := readHandshakeMessageTracked(reader, AlgorithmVersion, 1, 1, 64, progress)
	if err != nil {
		return nil, fmt.Errorf("%w: algorithm negotiation", ErrHandshake)
	}
	// The native camera decodes the recorder's offer but always selects 1.0.
	// Later PAKE parameters, proof verification and TLS trust remain mandatory.
	progress.details.OfferedBytes = len(version)
	progress.details.OfferVersion = "other"
	if string(version) == "1.0" {
		progress.details.OfferVersion = "1.0"
	}
	progress.stage = stageWriteVersion
	progress.details.Reason = "transport_write"
	if err := writeHandshakeMessage(writer, AlgorithmVersion, 2, []byte("1.0")); err != nil {
		return nil, err
	}
	progress.stage = stageReadParameters
	publicData, err := readHandshakeMessageTracked(reader, Spake2, 3, 36, 36, progress)
	if err != nil {
		return nil, err
	}
	progress.stage = stageDeriveShare
	progress.details.Reason = "pake_initialization"
	client, response, err := factory(publicData, authCode)
	if err != nil || client == nil || len(response) != 32 {
		if client != nil {
			client.Destroy()
		}
		return nil, fmt.Errorf("%w: PAKE initialization", ErrHandshake)
	}
	defer client.Destroy()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	progress.stage = stageWriteShare
	progress.details.Reason = "transport_write"
	if err := writeHandshakeMessage(writer, Spake2, 4, response); err != nil {
		return nil, err
	}
	progress.stage = stageReadProof
	proof, err := readHandshakeMessageTracked(reader, Spake2, 5, 64, 64, progress)
	if err != nil {
		return nil, err
	}
	progress.stage = stageVerifyProof
	progress.details.Reason = "pake_confirmation"
	response, keys, err := client.Finish(proof, "VIGI-IPC", "VIGI-NVR")
	defer clear(keys.Client[:])
	defer clear(keys.Server[:])
	if err != nil || len(response) != 32 {
		return nil, fmt.Errorf("%w: PAKE confirmation", ErrHandshake)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	progress.stage = stageWriteProof
	progress.details.Reason = "transport_write"
	if err := writeHandshakeMessage(writer, Spake2, 6, response); err != nil {
		return nil, err
	}
	progress.stage = stageReadCertificate
	encrypted, err := readHandshakeMessageTracked(reader, Spake2, 7, aes.BlockSize, maxCertificateBytes, progress)
	if err != nil {
		return nil, err
	}
	progress.stage = stageDecryptCertificate
	progress.details.Reason = "certificate_decode"
	return decryptCertificates(encrypted, keys)
}

// validAuthCode accepts a nonempty printable ASCII callback credential within
// the observed 64-byte limit.
func validAuthCode(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := range value {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// readHandshakeMessageTracked validates one expected step and decoded payload
// size, recording only fixed labels and public negotiation metadata on failure.
func readHandshakeMessageTracked(reader *bufio.Reader, contentType ContentType, step, minBytes, maxBytes int, progress *handshakeProgress) ([]byte, error) {
	progress.details.Reason = "frame_read"
	progress.details.PeerStepPresent, progress.details.PeerErrorCodePresent = false, false
	progress.details.PeerStep, progress.details.PeerErrorCode = 0, 0
	frame, err := ReadFrame(reader, true)
	if err != nil {
		var failure *frameReadFailure
		if errors.As(err, &failure) {
			progress.details.Reason, progress.details.PrefixCategory = failure.reason, failure.prefix
		}
		return nil, fmt.Errorf("%w: read step %d: %w", ErrHandshake, step, err)
	}
	progress.details.PrefixCategory = "native"
	var message handshakeMessage
	if json.Unmarshal(frame.Body, &message) != nil {
		progress.details.Reason = "json_fields"
		return nil, fmt.Errorf("%w: invalid step %d", ErrHandshake, step)
	}
	if message.Step != nil {
		progress.details.PeerStep, progress.details.PeerStepPresent = *message.Step, true
	}
	if message.ErrorCode != nil {
		progress.details.PeerErrorCode, progress.details.PeerErrorCodePresent = *message.ErrorCode, true
	}
	switch {
	case frame.ContentType != contentType:
		progress.details.Reason = "content_type"
	case message.Step == nil || *message.Step != step:
		progress.details.Reason = "unexpected_step"
	case message.ErrorCode == nil:
		progress.details.Reason = "missing_error_code"
	case *message.ErrorCode != 0:
		progress.details.Reason = "remote_error"
	case len(message.Data) > base64.StdEncoding.EncodedLen(maxBytes):
		progress.details.Reason = "data_size"
	default:
		progress.details.Reason = "base64_data"
	}
	if progress.details.Reason != "base64_data" {
		return nil, fmt.Errorf("%w: invalid step %d", ErrHandshake, step)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(message.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid step %d data", ErrHandshake, step)
	}
	if step == 1 {
		progress.details.OfferedBytes = len(data)
		progress.details.OfferVersion = "other"
		if string(data) == "1.0" {
			progress.details.OfferVersion = "1.0"
		}
	}
	if len(data) < minBytes || len(data) > maxBytes {
		progress.details.Reason = "data_size"
		return nil, fmt.Errorf("%w: invalid step %d data", ErrHandshake, step)
	}
	return data, nil
}

// writeHandshakeMessage emits one base64-encoded camera step and drains short
// writes; an invalid write count or transport failure aborts the exchange.
func writeHandshakeMessage(writer io.Writer, contentType ContentType, step int, data []byte) error {
	zero := 0
	body, err := json.Marshal(handshakeMessage{Step: &step, ErrorCode: &zero, Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return fmt.Errorf("%w: encode step %d", ErrHandshake, step)
	}
	encoded, err := Encode(Frame{ContentType: contentType, Body: body}, false)
	if err != nil {
		return fmt.Errorf("%w: frame step %d", ErrHandshake, step)
	}
	for len(encoded) > 0 {
		n, err := writer.Write(encoded)
		if err != nil || n <= 0 || n > len(encoded) {
			return fmt.Errorf("%w: write step %d", ErrHandshake, step)
		}
		encoded = encoded[n:]
	}
	return nil
}

// decryptCertificates derives the protocol's mixed directional AES key and IV,
// decrypts the bounded CBC payload, and clears temporary key/plaintext buffers.
func decryptCertificates(encrypted []byte, keys spakeee.Keys) ([]*x509.Certificate, error) {
	if len(encrypted) == 0 || len(encrypted) > maxCertificateBytes || len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: encrypted certificate size", ErrHandshake)
	}
	var key, iv [aes.BlockSize]byte
	copy(key[:8], keys.Server[:8])
	copy(key[8:], keys.Client[8:16])
	copy(iv[:8], keys.Client[:8])
	copy(iv[8:], keys.Server[8:16])
	defer clear(key[:])
	defer clear(iv[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: certificate cipher", ErrHandshake)
	}
	plain := make([]byte, len(encrypted))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plain, encrypted)
	return parseCertificates(plain)
}

// parseCertificates accepts a bounded PEM chain with the observed zero or
// PKCS#7 termination and rejects arbitrary suffixes or excessive certificates.
func parseCertificates(plain []byte) ([]*x509.Certificate, error) {
	if len(plain) == 0 || len(plain) > maxCertificateBytes {
		return nil, fmt.Errorf("%w: certificate size", ErrHandshake)
	}
	// Firmware consumes PEM text using strlen after raw CBC decryption. Accept
	// only bounded zero termination or verified PKCS#7, never arbitrary suffixes.
	if index := bytes.IndexByte(plain, 0); index >= 0 {
		if len(plain)-index > aes.BlockSize || !allBytes(plain[index:], 0) {
			return nil, fmt.Errorf("%w: certificate padding", ErrHandshake)
		}
		plain = plain[:index]
	} else if last := plain[len(plain)-1]; last > 0 && last <= aes.BlockSize {
		padding := int(last)
		if len(plain) >= padding && allBytes(plain[len(plain)-padding:], last) {
			plain = plain[:len(plain)-padding]
		} else if last != '\n' && last != '\r' {
			return nil, fmt.Errorf("%w: certificate padding", ErrHandshake)
		}
	}
	var certificates []*x509.Certificate
	for len(plain) > 0 {
		if !bytes.HasPrefix(plain, []byte("-----BEGIN CERTIFICATE-----")) || len(certificates) >= maxTrustedCertificates {
			return nil, fmt.Errorf("%w: certificate encoding", ErrHandshake)
		}
		block, rest := pem.Decode(plain)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("%w: certificate PEM", ErrHandshake)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate DER", ErrHandshake)
		}
		certificates = append(certificates, certificate)
		plain = rest
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: missing certificate", ErrHandshake)
	}
	return certificates, nil
}

// allBytes checks padding bytes for an exact repeated value; an empty slice
// has no mismatching byte.
func allBytes(data []byte, expected byte) bool {
	for _, value := range data {
		if value != expected {
			return false
		}
	}
	return true
}

// recorderTLSConfig pins TLS 1.2 trust to certificates from the authenticated
// PAKE exchange, using the recorder's curve preferences and custom verification.
func recorderTLSConfig(trusted []*x509.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		// The recorder's observed TLS1.2 connection uses secp521r1, which Go's
		// default curve list does not necessarily offer.
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256, tls.X25519},
		// Trust comes exclusively from this successful PAKE exchange. The native
		// peer ignores time/name mismatches; VerifyConnection still requires an
		// exact authenticated leaf or a valid chain to an authenticated anchor.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyRecorderCertificate(state.PeerCertificates, trusted)
		},
	}
}

// verifyRecorderCertificate requires an exact authenticated leaf or a valid
// server chain to a PAKE-authenticated anchor, without name or time matching.
func verifyRecorderCertificate(peers, trusted []*x509.Certificate) error {
	if len(peers) == 0 || len(peers) > maxTrustedCertificates || len(trusted) == 0 || len(trusted) > maxTrustedCertificates {
		return ErrPeerCertificate
	}
	for _, list := range [][]*x509.Certificate{peers, trusted} {
		for _, certificate := range list {
			if certificate == nil || len(certificate.Raw) == 0 {
				return ErrPeerCertificate
			}
		}
	}
	for _, certificate := range trusted {
		if bytes.Equal(peers[0].Raw, certificate.Raw) {
			return nil
		}
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, certificate := range trusted {
		roots.AddCert(withoutCertificateTime(certificate))
	}
	for _, certificate := range peers[1:] {
		intermediates.AddCert(withoutCertificateTime(certificate))
	}
	_, err := withoutCertificateTime(peers[0]).Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return ErrPeerCertificate
	}
	return nil
}

// withoutCertificateTime copies a certificate with a broad validity window
// for the native trust policy, leaving the original certificate unchanged.
func withoutCertificateTime(certificate *x509.Certificate) *x509.Certificate {
	clone := *certificate
	clone.NotBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	clone.NotAfter = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	return &clone
}

// bufferedConn preserves bytes read ahead during native negotiation so TLS
// consumes them before reading further from the underlying connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read consumes the shared negotiation buffer, retaining read-ahead TLS bytes.
func (c *bufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }
