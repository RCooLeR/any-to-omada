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

type handshakeFailure struct {
	diagnostics HandshakeDiagnostics
	cause       error
}

func (e *handshakeFailure) Error() string {
	return "omada callback handshake failed at " + e.diagnostics.Stage
}
func (e *handshakeFailure) Unwrap() error        { return e.cause }
func (e *handshakeFailure) Is(target error) bool { return target == ErrHandshake }

// stage belongs to the handshake goroutine; TLS may perform transport I/O from
// its cancellation goroutine, so only the byte counters need atomic access.
type handshakeProgress struct {
	stage    handshakeStage
	details  HandshakeDiagnostics
	received atomic.Int64
	sent     atomic.Int64
}

func (p *handshakeProgress) snapshot() HandshakeDiagnostics {
	result := p.details
	result.Stage, result.ReceivedBytes, result.SentBytes = string(p.stage), p.received.Load(), p.sent.Load()
	return result
}

type handshakeCountConn struct {
	net.Conn
	progress *handshakeProgress
}

func (c *handshakeCountConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.progress.received.Add(int64(n))
	}
	return n, err
}

func (c *handshakeCountConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.progress.sent.Add(int64(n))
	}
	return n, err
}
