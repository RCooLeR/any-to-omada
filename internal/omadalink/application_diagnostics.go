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

type applicationReadFailure struct {
	details ApplicationReadFailure
	cause   error
}

func (e *applicationReadFailure) Error() string {
	return "omada application frame failed at " + e.details.Stage + ": " + e.details.Reason
}

func (e *applicationReadFailure) Unwrap() error { return e.cause }

type applicationReadProgress struct {
	reader  *bufio.Reader
	details ApplicationReadFailure
}

func (p *applicationReadProgress) Read(data []byte) (int, error) {
	n, err := p.reader.Read(data)
	p.details.ReceivedBytes += n
	return n, err
}

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

// Keep the same limits and CRLF contract as readHeaderLine while counting bytes
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
