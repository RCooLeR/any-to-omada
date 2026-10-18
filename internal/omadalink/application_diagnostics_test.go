package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestApplicationDiagnosticsCountEveryTruncatedByte(t *testing.T) {
	heartbeat, err := EncodeHeartbeat(FirstMessageID)
	if err != nil {
		t.Fatal(err)
	}
	for _, leading := range []string{"", "\r\n"} {
		wire := append([]byte(leading), heartbeat...)
		for length := range len(wire) {
			_, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(wire[:length])))
			details, ok := ApplicationReadDiagnostics(err)
			if !ok || details.ReceivedBytes != length {
				t.Fatalf("leading %d, length %d: consumed %d, diagnostics %t", len(leading), length, details.ReceivedBytes, ok)
			}
			wantCause, wantReason := io.ErrUnexpectedEOF, "truncated"
			if length == 0 {
				wantCause, wantReason = io.EOF, "eof"
			}
			if !errors.Is(err, wantCause) || details.Reason != wantReason {
				t.Fatalf("leading %d, length %d: wrong error category: %v", len(leading), length, err)
			}
		}
	}
}

func TestApplicationDiagnosticsStagesAndMetadata(t *testing.T) {
	header := startBoundary + "Content-Type:Response\r\nContent-Length:2\r\n"
	for _, test := range []struct {
		name        string
		wire        string
		stage       string
		reason      string
		cause       error
		contentType ContentType
		declared    bool
		length      int
	}{
		{"prefix", "X", "prefix", "truncated", io.ErrUnexpectedEOF, "", false, 0},
		{"boundary", "--", "boundary", "truncated", io.ErrUnexpectedEOF, "", false, 0},
		{"header", startBoundary + "Content-Type:", "header", "truncated", io.ErrUnexpectedEOF, "", false, 0},
		{"header line ending", startBoundary + "Content-Type:Response\n", "header", "invalid_header", ErrInvalidFrame, "", false, 0},
		{"unknown header", startBoundary + "Unknown:private-marker\r\n", "header", "unknown_header", ErrInvalidFrame, "", false, 0},
		{"unknown type", startBoundary + "Content-Type:private-marker\r\n", "header", "unsupported_content_type", ErrInvalidFrame, "unknown", false, 0},
		{"duplicate header", startBoundary + "Content-Type:Response\r\nContent-Type:Request\r\n", "header", "duplicate_header", ErrInvalidFrame, ApplicationResponse, false, 0},
		{"invalid length", startBoundary + "Content-Type:Response\r\nContent-Length:private-marker\r\n", "header", "invalid_length", ErrInvalidFrame, ApplicationResponse, false, 0},
		{"short length", startBoundary + "Content-Type:Response\r\nContent-Length:1\r\n", "header", "invalid_length", ErrInvalidFrame, ApplicationResponse, true, 1},
		{"frame too large", startBoundary + "Content-Type:Response\r\nContent-Length:32768\r\n", "header", "frame_too_large", ErrFrameTooLarge, ApplicationResponse, true, 32768},
		{"body", header + "{", "body", "truncated", io.ErrUnexpectedEOF, ApplicationResponse, true, 2},
		{"trailer", header + "{}\r\n", "trailer", "truncated", io.ErrUnexpectedEOF, ApplicationResponse, true, 2},
		{"bad trailer", header + "{}" + strings.Repeat("x", len(endBoundary)), "trailer", "invalid_trailer", ErrInvalidFrame, ApplicationResponse, true, 2},
		{"JSON array", header + "[]" + endBoundary, "json", "invalid_json", ErrInvalidFrame, ApplicationResponse, true, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(test.wire)))
			details, ok := ApplicationReadDiagnostics(fmt.Errorf("outer: %w", err))
			if !ok || details.Stage != test.stage || details.Reason != test.reason || !errors.Is(err, test.cause) {
				t.Fatalf("unexpected failure: %+v, %v", details, err)
			}
			if details.ContentType != test.contentType || details.DeclaredBytesPresent != test.declared || details.DeclaredBytes != test.length || details.ReceivedBytes != len(test.wire) {
				t.Fatalf("unexpected metadata: %+v", details)
			}
		})
	}
}

func TestApplicationDiagnosticsExcludeBufferedReadAhead(t *testing.T) {
	wire := "HTTP/1.1 200 OK\r\nprivate-marker"
	reader := bufio.NewReader(strings.NewReader(wire))
	_, err := ReadApplicationFrame(reader)
	details, ok := ApplicationReadDiagnostics(err)
	if !ok || details.ReceivedBytes != 2 || reader.Buffered() != len(wire)-2 {
		t.Fatalf("read-ahead counted as consumed: %+v, buffered %d", details, reader.Buffered())
	}
	if details.Stage != "prefix" || details.Reason != "invalid_boundary" {
		t.Fatalf("unexpected prefix failure: %+v", details)
	}
}

func TestApplicationDiagnosticsBoundsAndRedaction(t *testing.T) {
	invalidBody := `{"secret":"private-marker"`
	invalidJSON := startBoundary + "Content-Type:Request\r\nContent-Length:" + strconv.Itoa(len(invalidBody)) + "\r\n" + invalidBody + endBoundary
	for _, wire := range []string{
		startBoundary + "Content-Type:private-marker\r\n",
		startBoundary + "private-marker:value\r\n",
		startBoundary + "Content-Length:private-marker\r\n",
		invalidJSON,
		startBoundary + strings.Repeat("private-marker", 20),
	} {
		_, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(wire)))
		details, ok := ApplicationReadDiagnostics(err)
		if !ok {
			t.Fatal("missing diagnostic snapshot")
		}
		encoded, marshalErr := json.Marshal(details)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if strings.Contains(err.Error(), "private-marker") || bytes.Contains(encoded, []byte("private-marker")) {
			t.Fatal("received data exposed by diagnostic error or snapshot")
		}
		if details.ReceivedBytes > MaxApplicationFrameSize {
			t.Fatal("consumed unbounded frame data")
		}
	}
	_, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(startBoundary + strings.Repeat("x", 200))))
	details, _ := ApplicationReadDiagnostics(err)
	if !errors.Is(err, ErrFrameTooLarge) || details.Reason != "frame_too_large" || details.ReceivedBytes != len(startBoundary)+maxHeaderLineSize {
		t.Fatalf("header bound changed: %+v, %v", details, err)
	}
	_, err = ReadApplicationFrame(nil)
	details, ok := ApplicationReadDiagnostics(err)
	if !ok || details.Reason != "invalid_reader" || details.ReceivedBytes != 0 || !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("nil reader diagnostics: %+v, %v", details, err)
	}
	if _, ok := ApplicationReadDiagnostics(io.EOF); ok {
		t.Fatal("unrelated error acquired application diagnostics")
	}
}

func TestApplicationDiagnosticsPreserveTransportErrors(t *testing.T) {
	header := startBoundary + "Content-Type:Request\r\nContent-Length:2\r\n"
	for _, test := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"timeout", &applicationTestTimeout{}, "timeout"},
		{"other transport", errors.New("private-marker"), "transport"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := io.MultiReader(strings.NewReader(header+"{"), applicationErrorReader{test.cause})
			_, err := ReadApplicationFrame(bufio.NewReader(source))
			details, ok := ApplicationReadDiagnostics(err)
			if !ok || details.Stage != "body" || details.Reason != test.reason || details.ReceivedBytes != len(header)+1 || !errors.Is(err, test.cause) {
				t.Fatalf("transport failure identity lost: %+v, %v", details, err)
			}
			var networkError net.Error
			if test.reason == "timeout" && (!errors.As(err, &networkError) || !networkError.Timeout()) {
				t.Fatal("timeout classification lost through wrapper")
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("underlying transport error reflected private data")
			}
		})
	}
}

func TestApplicationDiagnosticsLeaveAcceptedGrammarUnchanged(t *testing.T) {
	for _, contentType := range []ContentType{ApplicationRequest, ApplicationResponse, ApplicationDeclaration, ApplicationEvent} {
		body := ` {"method":"private-marker","nested":{"value":1}} `
		wire := "\r\n" + startBoundary + "Content-Length:\t" + strconv.Itoa(len(body)) + "\t\r\nContent-Type: " + string(contentType) + " \r\n" + body + endBoundary
		reader := bufio.NewReader(strings.NewReader(wire + "\r\n"))
		frame, err := ReadApplicationFrame(reader)
		if err != nil || frame.ContentType != contentType || string(frame.Body) != body {
			t.Fatalf("accepted frame changed: %v", err)
		}
		if reader.Buffered() != 2 {
			t.Fatal("trailing CRLF was consumed by current frame")
		}
		_, err = ReadApplicationFrame(reader)
		details, ok := ApplicationReadDiagnostics(err)
		if !ok || details.ReceivedBytes != 2 || details.LeadingCRLF != 1 || details.Stage != "boundary" || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("next frame did not own trailing CRLF: %+v, %v", details, err)
		}
	}
}

// applicationErrorReader injects a transport error before delivering bytes.
type applicationErrorReader struct{ err error }

// Read returns the configured failure without consuming or producing data.
func (r applicationErrorReader) Read([]byte) (int, error) { return 0, r.err }

// applicationTestTimeout supplies net.Error timeout semantics with private
// error text to test that diagnostics do not disclose underlying messages.
type applicationTestTimeout struct{}

// Error returns a sentinel string whose absence from diagnostics is asserted.
func (*applicationTestTimeout) Error() string { return "private-marker" }

// Timeout marks the synthetic failure as a network timeout.
func (*applicationTestTimeout) Timeout() bool { return true }

// Temporary keeps the synthetic timeout non-temporary for net.Error.
func (*applicationTestTimeout) Temporary() bool { return false }
