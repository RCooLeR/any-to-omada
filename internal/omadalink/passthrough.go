package omadalink

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxPassthroughFrameSize leaves room for the terminating NUL in the firmware's
// 20 KiB passthrough response buffer. Oversized responses are never truncated.
const MaxPassthroughFrameSize = 20*1024 - 1

// DecodePassthroughRequest decodes the string values inside an object-shaped
// requestData. Object keys and scalar types are unchanged. The firmware applies
// recursive percent decoding, not form decoding: a plus sign stays a plus sign.
// Malformed escapes, invalid UTF-8 and NUL-containing strings are rejected.
func DecodePassthroughRequest(data json.RawMessage) (json.RawMessage, error) {
	return codePassthroughObject(data, false)
}

// EncodePassthroughResponse returns the correlated native Response envelope for
// one dispatched management request. responseData is the complete management
// object, including its own error_code. The outer error_code is zero because
// dispatch completed, even when the management operation itself is unsupported.
// The response carries no method field and does not consume a camera-owned ID.
func EncodePassthroughResponse(id uint16, responseData json.RawMessage) ([]byte, error) {
	coded, err := codePassthroughObject(responseData, true)
	if err != nil {
		return nil, err
	}
	var status struct {
		ErrorCode *int32 `json:"error_code"`
	}
	if json.Unmarshal(responseData, &status) != nil || status.ErrorCode == nil {
		return nil, ErrInvalidFrame
	}
	body, err := json.Marshal(struct {
		ResponseData json.RawMessage `json:"responseData"`
		ID           uint16          `json:"id"`
		ErrorCode    int             `json:"error_code"`
	}{ResponseData: coded, ID: id})
	if err != nil {
		return nil, ErrInvalidFrame
	}
	header := startBoundary + "Content-Type:Response\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n"
	if len(header)+len(body)+len(endBoundary) > MaxPassthroughFrameSize {
		return nil, ErrFrameTooLarge
	}
	return []byte(header + string(body) + endBoundary), nil
}

// EncodeResponseStrings percent-encodes every string value of one JSON object
// with the native camera's encoder alphabet, for HTTPS responses that should
// match the donor's wire format. Member names and non-string values are unchanged.
func EncodeResponseStrings(data json.RawMessage) (json.RawMessage, error) {
	return codePassthroughObject(data, true)
}

// codePassthroughObject transforms string values in exactly one bounded JSON
// object, preserving numeric literals and rejecting extra trailing JSON.
func codePassthroughObject(data json.RawMessage, encode bool) (json.RawMessage, error) {
	if len(data) > MaxApplicationFrameSize {
		return nil, ErrFrameTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ErrInvalidFrame
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalidFrame
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrInvalidFrame
	}
	if err := codePassthroughValue(&value, encode, 0); err != nil {
		return nil, err
	}
	coded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	if len(coded) > MaxApplicationFrameSize {
		return nil, ErrFrameTooLarge
	}
	return coded, nil
}

// codePassthroughValue recursively transforms string leaves in place, limiting
// nesting to 64 levels and leaving object keys and non-string scalars unchanged.
func codePassthroughValue(value *any, encode bool, depth int) error {
	if depth > 64 {
		return ErrInvalidFrame
	}
	switch current := (*value).(type) {
	case map[string]any:
		for key, child := range current {
			if err := codePassthroughValue(&child, encode, depth+1); err != nil {
				return err
			}
			current[key] = child
		}
	case []any:
		for i := range current {
			if err := codePassthroughValue(&current[i], encode, depth+1); err != nil {
				return err
			}
		}
	case string:
		if encode {
			*value = encodePassthroughString(current)
			return nil
		}
		decoded, err := url.PathUnescape(current)
		if err != nil || !utf8.ValidString(decoded) || strings.IndexByte(decoded, 0) >= 0 {
			return ErrInvalidFrame
		}
		*value = decoded
	}
	return nil
}

// encodePassthroughString applies the firmware's byte-wise percent encoder,
// including its lowercase hex escapes and encodeURIComponent safe alphabet.
func encodePassthroughString(value string) string {
	// libjson's encoder preserves the encodeURIComponent alphabet and emits
	// lowercase hexadecimal escapes; it does not encode object member names.
	const hex = "0123456789abcdef"
	var output strings.Builder
	output.Grow(len(value))
	for i := range len(value) {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-_.!~*'()", rune(b)) {
			output.WriteByte(b)
		} else {
			output.WriteByte('%')
			output.WriteByte(hex[b>>4])
			output.WriteByte(hex[b&15])
		}
	}
	return output.String()
}
