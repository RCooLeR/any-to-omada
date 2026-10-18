// DVRIP framing and legacy challenge authentication shared by event capture and
// the isolated, explicitly configured lighting test client.
package dvripcapture

import (
	"bytes"
	"crypto/md5" // DVRIP requires the camera's legacy challenge algorithm.
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const maxPayload = 256 * 1024

// frame holds the fixed DVRIP header and its bounded payload as separate wire components.
type frame struct {
	header [32]byte
	body   []byte
}

// readFrame reads exactly one DVRIP frame, rejecting payloads above 256 KiB before allocating their buffer.
func readFrame(reader io.Reader) (frame, error) {
	var result frame
	if _, err := io.ReadFull(reader, result.header[:]); err != nil {
		return result, fmt.Errorf("read DVRIP header: %w", err)
	}
	length := binary.LittleEndian.Uint32(result.header[4:8])
	if length > maxPayload {
		return result, errors.New("DVRIP payload exceeds limit")
	}
	result.body = make([]byte, int(length))
	if _, err := io.ReadFull(reader, result.body); err != nil {
		return result, fmt.Errorf("read DVRIP payload: %w", err)
	}
	return result, nil
}

// writeFrame encodes a payload of at most 256 KiB and handles partial header/body writes.
func writeFrame(writer io.Writer, header [32]byte, body []byte) error {
	if len(body) > maxPayload {
		return errors.New("DVRIP request exceeds limit")
	}
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(body)))
	for _, part := range [][]byte{header[:], body} {
		for len(part) > 0 {
			written, err := writer.Write(part)
			if err != nil {
				return fmt.Errorf("write DVRIP frame: %w", err)
			}
			if written == 0 {
				return io.ErrShortWrite
			}
			part = part[written:]
		}
	}
	return nil
}

// challengeHeader constructs the legacy DVRIP request that obtains the login realm and random challenge.
func challengeHeader() [32]byte {
	return [32]byte{0: 0xa0, 1: 0x01, 24: 0x05, 25: 0x02, 26: 0x01, 27: 0x01, 30: 0xa1, 31: 0xaa}
}

// loginHeader constructs the legacy DVRIP envelope for the challenge response.
func loginHeader() [32]byte {
	return [32]byte{0: 0xa0, 1: 0x05, 24: 0x05, 25: 0x02, 27: 0x08, 30: 0xa1, 31: 0xaa}
}

// latin1 encodes legacy authentication text, rejecting characters that cannot be represented
// by a single Latin-1 byte.
func latin1(value string) ([]byte, error) {
	result := make([]byte, 0, len(value))
	for _, char := range value {
		if char > 255 {
			return nil, errors.New("DVRIP legacy authentication requires Latin-1 characters")
		}
		result = append(result, byte(char))
	}
	return result, nil
}

// fromLatin1 decodes device bytes without losing their values when the camera omits UTF-8 encoding.
func fromLatin1(value []byte) string {
	var result strings.Builder
	result.Grow(len(value))
	for _, char := range value {
		result.WriteRune(rune(char))
	}
	return result.String()
}

// loginPayload combines the two legacy challenge responses required by DVRIP; it never
// includes the plaintext password.
func loginPayload(username, password string, challenge []byte) ([]byte, error) {
	var realm, nonce string
	for _, line := range strings.Split(fromLatin1(challenge), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if value, found := strings.CutPrefix(line, "Realm:"); found {
			realm = value
		}
		if value, found := strings.CutPrefix(line, "Random:"); found {
			nonce = value
		}
	}
	if realm == "" || nonce == "" {
		return nil, errors.New("DVRIP authentication challenge is incomplete")
	}
	userBytes, err := latin1(username)
	if err != nil {
		return nil, err
	}
	passwordBytes, err := latin1(password)
	if err != nil {
		return nil, err
	}
	// All concatenated values have been checked or decoded as Latin-1.
	hash := func(value string) string {
		encoded, _ := latin1(value)
		digest := md5.Sum(encoded)
		return strings.ToUpper(hex.EncodeToString(digest[:]))
	}
	first := hash(username + ":" + realm + ":" + password)
	second := hash(username + ":" + nonce + ":" + first)
	digest := md5.Sum(passwordBytes)
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	compressed := make([]byte, 8)
	for i := range compressed {
		compressed[i] = alphabet[(int(digest[2*i])+int(digest[2*i+1]))%len(alphabet)]
	}
	legacy := hash(username + ":" + nonce + ":" + string(compressed))
	return append(userBytes, []byte("&&"+second+legacy)...), nil
}

// jsonMessages decodes concatenated DVRIP JSON objects, preserving numbers and sanitizing
// parse errors that could contain device data.
func jsonMessages(body []byte) ([]map[string]any, error) {
	body = bytes.Trim(body, "\x00\r\n\t ")
	if !utf8.Valid(body) {
		body = []byte(fromLatin1(body))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var messages []map[string]any
	for {
		var message map[string]any
		if err := decoder.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				return messages, nil
			}
			// JSON errors may contain device data; do not include their text.
			return nil, errors.New("invalid DVRIP JSON payload")
		}
		if message == nil {
			return nil, errors.New("DVRIP response is not an object")
		}
		messages = append(messages, message)
	}
}
