// Package omadalink implements native callback framing, authentication, TLS
// upgrade and application messages from the observed Omada protocol.
package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const (
	// MaxFrameSize bounds the entire encoded frame, including headers and trailer.
	MaxFrameSize      = 64 * 1024
	maxHeaderLineSize = 128
	maxLeadingCRLF    = 4
	startBoundary     = "--start-boundary--\r\n"
	endBoundary       = "\r\n--end-boundary--"
)

// ContentType identifies one of the two observed envelope types.
type ContentType string

const (
	// AlgorithmVersion identifies the initial algorithm-negotiation envelope.
	AlgorithmVersion ContentType = "ALG_Ver"
	// Spake2 identifies the subsequent envelope without interpreting its payload.
	Spake2 ContentType = "Spake2"
)

var (
	// ErrInvalidFrame indicates malformed framing, an unsupported type or invalid JSON.
	ErrInvalidFrame = errors.New("invalid omada callback frame")
	// ErrFrameTooLarge indicates a frame or header exceeding its fixed size bound.
	ErrFrameTooLarge = errors.New("omada callback frame exceeds size limit")
)

// Frame holds an opaque JSON payload. Body may contain authentication material;
// callers must not log it. Decode and encode preserve its bytes without normalizing
// JSON, interpreting fields or validating cryptographic values.
type Frame struct {
	ContentType ContentType
	Body        json.RawMessage
}

// ReadFrame reads one envelope from the caller's existing buffered reader.
// trailingCRLF selects the observed NVR ending (true) or camera ending (false).
// It is explicit because looking ahead for an optional trailer could block while
// a camera waits for a reply. No bytes beyond that selected ending are consumed.
// Continue using r after the final frame so buffered TLS bytes are preserved.
// Up to four leading empty CRLF lines are accepted within the frame size bound.
// Callers own deadlines and step sequencing. After an error the stream may have
// been partly consumed and must not be retried as a fresh frame.
func ReadFrame(r *bufio.Reader, trailingCRLF bool) (_ Frame, err error) {
	reason, prefix := "frame_boundary", "not_read"
	defer func() {
		if err != nil {
			err = &frameReadFailure{reason: reason, prefix: prefix, cause: err}
		}
	}()
	if r == nil {
		return Frame{}, ErrInvalidFrame
	}
	consumed := 0
	for {
		first, peekErr := r.Peek(2)
		if len(first) != 0 {
			prefix = "other"
		}
		if peekErr != nil {
			if len(first) != 0 || consumed != 0 {
				peekErr = incomplete(peekErr)
			}
			return Frame{}, peekErr
		}
		if !bytes.Equal(first, []byte("\r\n")) {
			break
		}
		if consumed == 2*maxLeadingCRLF {
			reason = "frame_prefix_limit"
			return Frame{}, ErrInvalidFrame
		}
		_, _ = r.Discard(2)
		consumed += 2
	}
	first, _ := r.Peek(4)
	switch {
	case bytes.HasPrefix(first, []byte("--")):
		prefix = "native"
	case bytes.Equal(first, []byte("HTTP")):
		prefix = "http"
	case len(first) >= 2 && first[0] >= 20 && first[0] <= 23 && first[1] == 3:
		prefix = "tls"
	}
	if err := readLiteral(r, startBoundary); err != nil {
		return Frame{}, incomplete(err)
	}
	consumed += len(startBoundary)
	reason = "frame_header"
	var contentType ContentType
	length := -1
	for range 2 {
		line, err := readHeaderLine(r)
		if err != nil {
			return Frame{}, incomplete(err)
		}
		consumed += len(line) + 2
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			return Frame{}, ErrInvalidFrame
		}
		value = bytes.Trim(value, " \t")
		switch string(key) {
		case "Content-Type":
			if contentType != "" || !validType(ContentType(value)) {
				reason = "frame_content_type"
				return Frame{}, ErrInvalidFrame
			}
			contentType = ContentType(value)
		case "Content-Length":
			if length != -1 {
				return Frame{}, ErrInvalidFrame
			}
			length, err = decimalLength(value)
			if err != nil {
				reason = "frame_length"
				return Frame{}, err
			}
		default:
			return Frame{}, ErrInvalidFrame
		}
	}
	if contentType == "" || length < 1 {
		return Frame{}, ErrInvalidFrame
	}
	ending := endBoundary
	if trailingCRLF {
		ending += "\r\n"
	}
	if length > MaxFrameSize-consumed-len(ending) {
		reason = "frame_size"
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, length)
	reason = "frame_body"
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, incomplete(err)
	}
	reason = "frame_ending"
	if err := readLiteral(r, ending); err != nil {
		return Frame{}, incomplete(err)
	}
	if !json.Valid(body) {
		reason = "frame_json"
		return Frame{}, ErrInvalidFrame
	}
	return Frame{ContentType: contentType, Body: body}, nil
}

// frameReadFailure exposes only fixed parser categories, never received bytes.
type frameReadFailure struct {
	reason string
	prefix string
	cause  error
}

// Error describes the fixed envelope-failure category without received bytes.
func (e *frameReadFailure) Error() string { return "invalid callback envelope: " + e.reason }

// Unwrap exposes the framing or transport cause for errors.Is/errors.As.
func (e *frameReadFailure) Unwrap() error { return e.cause }

// Encode returns a bounded envelope containing the exact Body bytes.
// trailingCRLF selects the NVR wire form (true) or camera wire form (false),
// including their observed Content-Length spacing and frame ending.
// It performs no I/O and does not interpret the JSON fields.
func Encode(frame Frame, trailingCRLF bool) ([]byte, error) {
	if !validType(frame.ContentType) {
		return nil, ErrInvalidFrame
	}
	if len(frame.Body) > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	lengthSeparator := ""
	if trailingCRLF {
		lengthSeparator = " "
	}
	// These are native protocol headers, not HTTP headers. Preserve the captured
	// spelling: neither peer spaces Content-Type; only the NVR spaces the length.
	header := startBoundary + "Content-Type:" + string(frame.ContentType) + "\r\nContent-Length:" + lengthSeparator + strconv.Itoa(len(frame.Body)) + "\r\n"
	ending := endBoundary
	if trailingCRLF {
		ending += "\r\n"
	}
	if len(frame.Body) > MaxFrameSize-len(header)-len(ending) {
		return nil, ErrFrameTooLarge
	}
	if !json.Valid(frame.Body) {
		return nil, ErrInvalidFrame
	}
	encoded := make([]byte, 0, len(header)+len(frame.Body)+len(ending))
	encoded = append(encoded, header...)
	encoded = append(encoded, frame.Body...)
	return append(encoded, ending...), nil
}

// validType limits pre-TLS envelopes to algorithm negotiation and SPAKE2.
func validType(value ContentType) bool {
	return value == AlgorithmVersion || value == Spake2
}

// readLiteral consumes exactly the requested boundary and rejects mismatches
// without reading ahead into the next protocol step.
func readLiteral(r *bufio.Reader, expected string) error {
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(r, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, []byte(expected)) {
		return ErrInvalidFrame
	}
	return nil
}

// readHeaderLine reads one CRLF-terminated header within maxHeaderLineSize
// and returns its bytes without the CRLF.
func readHeaderLine(r *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, maxHeaderLineSize)
	for range maxHeaderLineSize {
		value, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
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

// decimalLength accepts only unsigned decimal digits and rejects values above
// MaxFrameSize before callers allocate a body buffer.
func decimalLength(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, ErrInvalidFrame
	}
	length := 0
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrInvalidFrame
		}
		length = length*10 + int(digit-'0')
		if length > MaxFrameSize {
			return 0, ErrFrameTooLarge
		}
	}
	return length, nil
}

// incomplete turns an end-of-stream encountered inside a frame into
// io.ErrUnexpectedEOF while preserving other parser and transport failures.
func incomplete(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
