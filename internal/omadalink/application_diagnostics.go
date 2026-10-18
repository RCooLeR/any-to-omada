package omadalink

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

// ApplicationReadFailure describes one failed application frame read using fixed
// parser categories and byte counts. ReceivedBytes counts bytes consumed from
// the buffered reader, excluding read-ahead. DeclaredBytes is valid only when
// DeclaredBytesPresent is true. ContentType is empty until a type is read, then
// one of the accepted application types or "unknown". No payload is retained.
type ApplicationReadFailure struct {
	Stage                string
	Reason               string
	ReceivedBytes        int
	DeclaredBytes        int
	DeclaredBytesPresent bool
	ContentType          ContentType
	LeadingCRLF          int
}

// ApplicationReadDiagnostics retrieves the diagnostic snapshot attached by
// ReadApplicationFrame, including through wrapped errors. Other errors return
// false. The underlying error remains available through errors.Is/errors.As.
func ApplicationReadDiagnostics(err error) (ApplicationReadFailure, bool) {
	var failure *applicationReadFailure
	if !errors.As(err, &failure) {
		return ApplicationReadFailure{}, false
	}
	return failure.details, true
}

// applicationReadFailure retains a payload-free parser snapshot and its cause
// so diagnostics and errors.Is/errors.As can inspect the same failure.
type applicationReadFailure struct {
	details ApplicationReadFailure
	cause   error
}

// Error formats fixed parser labels without exposing the underlying payload or
// transport error text.
func (e *applicationReadFailure) Error() string {
	return "omada application frame failed at " + e.details.Stage + ": " + e.details.Reason
}

// Unwrap preserves the original parser or transport error for error matching.
func (e *applicationReadFailure) Unwrap() error { return e.cause }

// applicationReadProgress tracks consumed bytes for a single frame; buffered
// read-ahead belongs to subsequent frames and is not included.
type applicationReadProgress struct {
	reader  *bufio.Reader
	details ApplicationReadFailure
}

// Read delegates to the buffered reader and counts even partially successful
// reads before returning their error.
func (p *applicationReadProgress) Read(data []byte) (int, error) {
	n, err := p.reader.Read(data)
	p.details.ReceivedBytes += n
	return n, err
}

// failure snapshots progress, deriving a fixed failure category only when the
// parser has not already supplied a more specific reason.
func (p *applicationReadProgress) failure(err error) error {
	if p.details.Reason == "" {
		var networkError net.Error
		switch {
		case errors.Is(err, io.EOF):
			p.details.Reason = "eof"
		case errors.Is(err, io.ErrUnexpectedEOF):
			p.details.Reason = "truncated"
		case errors.As(err, &networkError) && networkError.Timeout():
			p.details.Reason = "timeout"
		case errors.Is(err, ErrFrameTooLarge):
			p.details.Reason = "frame_too_large"
		case errors.Is(err, ErrInvalidFrame):
			p.details.Reason = "invalid_" + p.details.Stage
		default:
			p.details.Reason = "transport"
		}
	}
	return &applicationReadFailure{details: p.details, cause: err}
}

// readLiteral consumes exactly the expected boundary bytes and rejects any
// difference without storing received content in diagnostics.
func (p *applicationReadProgress) readLiteral(expected string) error {
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(p, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, []byte(expected)) {
		return ErrInvalidFrame
	}
	return nil
}

// readHeaderLine keeps the package header parser's limits and CRLF contract while counting bytes
// consumed, including incomplete and malformed lines. Buffered read-ahead is not
// part of the failed frame and must not inflate its diagnostic count.
func (p *applicationReadProgress) readHeaderLine() ([]byte, error) {
	line := make([]byte, 0, maxHeaderLineSize)
	for range maxHeaderLineSize {
		value, err := p.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		p.details.ReceivedBytes++
		line = append(line, value)
		if value == '\n' {
			if len(line) < 2 || line[len(line)-2] != '\r' {
				return nil, ErrInvalidFrame
			}
			return line[:len(line)-2], nil
		}
	}
	return nil, ErrFrameTooLarge
}
