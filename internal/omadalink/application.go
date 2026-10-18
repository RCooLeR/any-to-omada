package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

const (
	// MaxApplicationFrameSize matches the donor's 32 KiB receive accumulator.
	MaxApplicationFrameSize = 32 * 1024
	// ApplicationRequest carries requests including camera heartbeats.
	ApplicationRequest ContentType = "Request"
	// ApplicationResponse carries responses to application requests.
	ApplicationResponse ContentType = "Response"
	// ApplicationDeclaration carries a connection's device declaration.
	ApplicationDeclaration ContentType = "Declaration"
	// ApplicationEvent preserves the firmware's misspelled event content type.
	ApplicationEvent ContentType = "Nofity_Event"
	// ApplicationAuthRequest carries the post-TLS camera-account Digest proof.
	ApplicationAuthRequest ContentType = "Auth"
)

// ReadApplicationFrame reads one bounded JSON object after TLS authentication.
// It does not execute requests or interpret JSON methods. Accepted types match
// donor firmware and the decrypted camera/recorder enrollment capture.
// Unlike the donor's delimiter search, this decoder enforces Content-Length.
//
// A trailing CRLF is left for the next call, which accepts at most one leading
// CRLF. This supports both observed envelope endings without looking ahead and
// blocking a caller waiting to reply. Continue using the same buffered reader.
// Callers own deadlines, authentication and method validation. After an error,
// discard the connection: the partially consumed frame cannot safely be retried.
// ApplicationReadDiagnostics describes failures without retaining payload data;
// errors.Is/errors.As still expose the underlying parser or transport cause.
func ReadApplicationFrame(r *bufio.Reader) (_ Frame, err error) {
	progress := applicationReadProgress{reader: r}
	progress.details.Stage = "prefix"
	defer func() {
		if err != nil {
			err = progress.failure(err)
		}
	}()
	if r == nil {
		progress.details.Reason = "invalid_reader"
		return Frame{}, ErrInvalidFrame
	}
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(&progress, prefix); err != nil {
		return Frame{}, err
	}
	consumed := 0
	if bytes.Equal(prefix, []byte("\r\n")) {
		consumed = 2
		progress.details.LeadingCRLF = 1
		progress.details.Stage = "boundary"
		if err := progress.readLiteral(startBoundary); err != nil {
			return Frame{}, incomplete(err)
		}
	} else {
		if !bytes.Equal(prefix, []byte("--")) {
			progress.details.Reason = "invalid_boundary"
			return Frame{}, ErrInvalidFrame
		}
		progress.details.Stage = "boundary"
		if err := progress.readLiteral(startBoundary[2:]); err != nil {
			return Frame{}, incomplete(err)
		}
	}
	consumed += len(startBoundary)
	progress.details.Stage = "header"
	var contentType ContentType
	length := -1
	for range 2 {
		line, err := progress.readHeaderLine()
		if err != nil {
			return Frame{}, incomplete(err)
		}
		consumed += len(line) + 2
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			progress.details.Reason = "invalid_header"
			return Frame{}, ErrInvalidFrame
		}
		value = bytes.Trim(value, " \t")
		switch string(key) {
		case "Content-Type":
			if contentType != "" {
				progress.details.Reason = "duplicate_header"
				return Frame{}, ErrInvalidFrame
			}
			if !applicationType(ContentType(value)) {
				progress.details.ContentType = "unknown"
				progress.details.Reason = "unsupported_content_type"
				return Frame{}, ErrInvalidFrame
			}
			contentType = ContentType(value)
			progress.details.ContentType = contentType
		case "Content-Length":
			if length != -1 {
				progress.details.Reason = "duplicate_header"
				return Frame{}, ErrInvalidFrame
			}
			length, err = decimalLength(value)
			if err != nil {
				progress.details.Reason = "invalid_length"
				return Frame{}, err
			}
			progress.details.DeclaredBytes = length
			progress.details.DeclaredBytesPresent = true
		default:
			progress.details.Reason = "unknown_header"
			return Frame{}, ErrInvalidFrame
		}
	}
	if contentType == "" || length < 2 {
		progress.details.Reason = "invalid_length"
		return Frame{}, ErrInvalidFrame
	}
	if length > MaxApplicationFrameSize-consumed-len(endBoundary) {
		progress.details.Reason = "frame_too_large"
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, length)
	progress.details.Stage = "body"
	if _, err := io.ReadFull(&progress, body); err != nil {
		return Frame{}, incomplete(err)
	}
	progress.details.Stage = "trailer"
	if err := progress.readLiteral(endBoundary); err != nil {
		return Frame{}, incomplete(err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(body) {
		progress.details.Stage = "json"
		progress.details.Reason = "invalid_json"
		return Frame{}, ErrInvalidFrame
	}
	return Frame{ContentType: contentType, Body: body}, nil
}

func applicationType(value ContentType) bool {
	return value == ApplicationRequest || value == ApplicationResponse ||
		value == ApplicationDeclaration || value == ApplicationEvent || value == ApplicationAuthRequest
}
