package omadalink

import (
	"errors"
	"net"
	"sync/atomic"
)

// HandshakeDiagnostics describes a failure using fixed categories, byte counts
// and public negotiation metadata. Peer fields describe the current read only;
// offer fields describe the initial algorithm offer throughout the exchange.
// It contains no peer identity or authentication payload.
type HandshakeDiagnostics struct {
	Stage                string
	ReceivedBytes        int64
	SentBytes            int64
	Reason               string
	PrefixCategory       string
	PeerStep             int
	PeerStepPresent      bool
	PeerErrorCode        int
	PeerErrorCodePresent bool
	OfferedBytes         int
	OfferVersion         string
}

// FailureDiagnostics returns a snapshot attached to a Handshake failure, even
// when the caller has wrapped it. Unrelated errors return false.
func FailureDiagnostics(err error) (HandshakeDiagnostics, bool) {
	var failure *handshakeFailure
	if !errors.As(err, &failure) {
		return HandshakeDiagnostics{}, false
	}
	return failure.diagnostics, true
}

type handshakeStage string

const (
	stageValidateRegistration handshakeStage = "validate_registration"
	stageSetDeadline          handshakeStage = "set_deadline"
	stageReadVersion          handshakeStage = "read_version"
	stageWriteVersion         handshakeStage = "write_version"
	stageReadParameters       handshakeStage = "read_parameters"
	stageDeriveShare          handshakeStage = "derive_share"
	stageWriteShare           handshakeStage = "write_share"
	stageReadProof            handshakeStage = "read_proof"
	stageVerifyProof          handshakeStage = "verify_proof"
	stageWriteProof           handshakeStage = "write_proof"
	stageReadCertificate      handshakeStage = "read_certificate"
	stageDecryptCertificate   handshakeStage = "decrypt_certificate"
	stageTLS                  handshakeStage = "tls"
	stageClearDeadline        handshakeStage = "clear_deadline"
)

// handshakeFailure attaches non-secret progress to an underlying failure and
// also matches ErrHandshake regardless of the transport cause.
type handshakeFailure struct {
	diagnostics HandshakeDiagnostics
	cause       error
}

// Error identifies the failed handshake stage without exposing peer data.
func (e *handshakeFailure) Error() string {
	return "omada callback handshake failed at " + e.diagnostics.Stage
}

// Unwrap exposes the underlying transport, context or authentication failure.
func (e *handshakeFailure) Unwrap() error { return e.cause }

// Is classifies every wrapped handshake failure as ErrHandshake.
func (e *handshakeFailure) Is(target error) bool { return target == ErrHandshake }

// handshakeProgress belongs to the handshake goroutine except for its atomic
// byte counters: TLS can also perform transport I/O from cancellation goroutines.
type handshakeProgress struct {
	stage    handshakeStage
	details  HandshakeDiagnostics
	received atomic.Int64
	sent     atomic.Int64
}

// snapshot copies the handshake goroutine's stage and atomically sampled byte
// counters, excluding authentication material.
func (p *handshakeProgress) snapshot() HandshakeDiagnostics {
	result := p.details
	result.Stage, result.ReceivedBytes, result.SentBytes = string(p.stage), p.received.Load(), p.sent.Load()
	return result
}

// handshakeCountConn counts transport bytes, including TLS I/O, without
// retaining their contents or changing net.Conn deadline semantics.
type handshakeCountConn struct {
	net.Conn
	progress *handshakeProgress
}

// Read adds the bytes actually received to handshake diagnostics, including
// partial reads accompanied by an error.
func (c *handshakeCountConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.progress.received.Add(int64(n))
	}
	return n, err
}

// Write adds only successfully written bytes to handshake diagnostics.
func (c *handshakeCountConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.progress.sent.Add(int64(n))
	}
	return n, err
}
