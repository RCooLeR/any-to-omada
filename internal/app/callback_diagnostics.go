package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const callbackTraceFrameLimit = 16

var callbackMethodName = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// callbackMethodLabel keeps a recorder method name only when it is a plain identifier.
func callbackMethodLabel(method string) string {
	if callbackMethodName.MatchString(method) {
		return method
	}
	return "?"
}

type callbackFrameMetadata struct {
	contentType   omadalink.ContentType
	bodyBytes     int
	method        string
	requestKind   string
	responseKind  string
	id            uint16
	idPresent     bool
	errorCode     int32
	errorPresent  bool
	responseError int32
	responseSet   bool
}

type callbackReadFailure struct {
	err       error
	stage     string
	frames    uint64
	elapsed   time.Duration
	lastFrame callbackFrameMetadata
}

// readCallback records bounded metadata before method-specific decoding. Native
// passthrough data is an object; strings remain invalid and are never executed.
func (c *callback) readCallback(ctx context.Context, conn net.Conn, messages chan<- callbackMessage, failures chan<- callbackReadFailure) {
	reader := bufio.NewReader(conn)
	started := time.Now()
	var frames uint64
	var last callbackFrameMetadata
	fail := func(stage string, err error) {
		failures <- callbackReadFailure{err: err, stage: stage, frames: frames, elapsed: time.Since(started), lastFrame: last}
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(45 * time.Second)); err != nil {
			fail("set_deadline", err)
			return
		}
		frame, err := omadalink.ReadApplicationFrame(reader)
		if err != nil {
			fail("frame", err)
			return
		}
		frames++
		last = callbackMetadata(frame)
		if frames <= callbackTraceFrameLimit {
			fields := append([]any{"frame_number", frames}, last.fields()...)
			c.logger.Info("native callback message received", fields...)
		} else if frames == callbackTraceFrameLimit+1 {
			c.logger.Info("native callback message trace limit reached", "frame_limit", callbackTraceFrameLimit)
		}
		message, err := decodeCallbackMessage(frame.Body)
		if err != nil {
			fail("message", err)
			return
		}
		select {
		case messages <- message:
		case <-ctx.Done():
			return
		}
	}
}

func callbackMetadata(frame omadalink.Frame) callbackFrameMetadata {
	result := callbackFrameMetadata{contentType: frame.ContentType, bodyBytes: len(frame.Body), method: "unknown"}
	var fields map[string]json.RawMessage
	if json.Unmarshal(frame.Body, &fields) != nil {
		return result
	}
	var method string
	if json.Unmarshal(fields["method"], &method) == nil {
		switch method {
		case "heartbeat", "declaration", "response", "auth", "passthrough", "request", "notify":
			result.method = method
		}
	}
	result.requestKind = callbackJSONKind(fields["requestData"])
	result.responseKind = callbackJSONKind(fields["responseData"])
	result.idPresent = callbackJSONKind(fields["id"]) == "number" && json.Unmarshal(fields["id"], &result.id) == nil
	result.errorPresent = callbackJSONKind(fields["error_code"]) == "number" && json.Unmarshal(fields["error_code"], &result.errorCode) == nil
	if len(fields["method"]) == 0 && result.errorPresent && frame.ContentType == omadalink.ApplicationResponse {
		result.method = "response"
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(fields["responseData"], &response) == nil {
		result.responseSet = callbackJSONKind(response["error_code"]) == "number" && json.Unmarshal(response["error_code"], &result.responseError) == nil
	}
	return result
}

func (m callbackFrameMetadata) fields() []any {
	fields := []any{"content_type", m.contentType, "body_bytes", m.bodyBytes, "method", m.method,
		"request_data_kind", m.requestKind, "response_data_kind", m.responseKind}
	if m.idPresent {
		fields = append(fields, "message_id", m.id)
	}
	if m.errorPresent {
		fields = append(fields, "message_error_code", m.errorCode)
	}
	if m.responseSet {
		fields = append(fields, "response_error_code", m.responseError)
	}
	return fields
}

func callbackJSONKind(value json.RawMessage) string {
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return "missing"
	}
	switch value[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 'n':
		return "null"
	case 't', 'f':
		return "boolean"
	default:
		return "number"
	}
}

func (c *callback) logCallbackReadFailure(failure callbackReadFailure, heartbeatsSent uint64, unanswered int) {
	fields := []any{"read_stage", failure.stage, "failure_kind", callbackFailureKind(failure.err),
		"frames_received", failure.frames, "elapsed_ms", failure.elapsed.Milliseconds(),
		"heartbeats_sent", heartbeatsSent, "unanswered_heartbeats", unanswered}
	if failure.frames > 0 {
		fields = append(fields, "last_message", failure.lastFrame.method, "last_request_data_kind", failure.lastFrame.requestKind,
			"last_content_type", failure.lastFrame.contentType)
	}
	if detail, ok := omadalink.ApplicationReadDiagnostics(failure.err); ok {
		fields = append(fields, "frame_stage", detail.Stage, "failure_reason", detail.Reason,
			"received_bytes", detail.ReceivedBytes, "leading_crlf", detail.LeadingCRLF)
		if detail.ContentType != "" {
			fields = append(fields, "content_type", detail.ContentType)
		}
		if detail.DeclaredBytesPresent {
			fields = append(fields, "declared_bytes", detail.DeclaredBytes)
		}
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(failure.err, &typeError) {
		field := "unknown"
		switch typeError.Field {
		case "id", "method", "requestData", "requestData.version", "responseData", "responseData.error_code":
			field = typeError.Field
		}
		fields = append(fields, "message_field", field)
	}
	// Underlying error text may contain payload fragments or peer addresses.
	c.logger.Warn("native callback read failed", fields...)
}

func callbackFailureKind(err error) string {
	var typeError *json.UnmarshalTypeError
	var networkError net.Error
	switch {
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		return "timeout"
	case errors.As(err, &typeError):
		return "message_type"
	case errors.Is(err, omadalink.ErrFrameTooLarge):
		return "frame_too_large"
	case errors.Is(err, omadalink.ErrInvalidFrame):
		return "invalid_frame"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed"
	default:
		return "transport"
	}
}
