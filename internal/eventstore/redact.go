package eventstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type redactor struct{ secrets []string }

var sensitiveXML = regexp.MustCompile(`(?is)<(?:[\w.-]+:)?(Security|Username|Password|Nonce|SerialNumber|HardwareId|SubscriptionReference|ReferenceParameters|ProducerReference)(?:\s[^>]*)?>.*?</(?:[\w.-]+:)?(?:Security|Username|Password|Nonce|SerialNumber|HardwareId|SubscriptionReference|ReferenceParameters|ProducerReference)\s*>`)
var urlUserInfo = regexp.MustCompile(`(?i)(https?|rtsp)://[^\s<>"/@]+(?::[^\s<>"/@]*)?@`)
var secretQuery = regexp.MustCompile(`(?i)([?&](?:password|passwd|token|access_token|session|sid|auth)=)[^\s<>"&]+`)
var stokPath = regexp.MustCompile(`(?i)(/stok=)[^/\s<>"?]+`)

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
	for _, secret := range []string{"password", "passwd", "authorization", "authcode", "credential", "privatekey", "secret", "token", "cookie"} {
		if strings.Contains(key, secret) {
			return true
		}
	}
	switch key {
	case "password", "passwd", "pwd", "username", "user", "authorization", "proxyauthorization", "cookie", "setcookie", "secret", "apikey", "token", "accesstoken", "refreshtoken", "session", "sessionid", "loginhandle", "nonce", "digest", "serialnumber", "serial", "sn", "hardwareid", "subscriptionreference", "referenceparameters", "consumerreference", "producerreference":
		return true
	}
	return false
}

func binaryKey(key string) bool {
	switch strings.ToLower(key) {
	case "picture", "image", "jpeg", "jpg", "thumbnail", "picturedata", "imagedata", "data64", "base64image", "faceimage":
		return true
	}
	return false
}

func (l *redactor) redact(value any, depth int) any {
	if depth > 40 {
		return "[depth limit]"
	}
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range typed {
			if sensitiveKey(key) {
				result[key] = "[redacted]"
			} else if binaryKey(key) {
				raw, _ := json.Marshal(item)
				sum := sha256.Sum256(raw)
				result[key] = map[string]any{"omitted": "binary_payload", "bytes": len(raw), "sha256": hex.EncodeToString(sum[:])}
			} else {
				result[key] = l.redact(item, depth+1)
			}
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = l.redact(item, depth+1)
		}
		return result
	case string:
		// JSON embedded in Data.event must retain its semantic fields, with the
		// same secret redaction as a normal native JSON event.
		trimmed := strings.TrimSpace(typed)
		if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
			var nested any
			if decodeJSON([]byte(trimmed), &nested) == nil {
				sanitized, _ := json.Marshal(l.redact(nested, depth+1))
				return string(sanitized)
			}
		}
		if len(trimmed) >= 4 {
			if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
				var nested any
				body := bytes.TrimSpace(decoded)
				if len(body) > 1 && (body[0] == '{' || body[0] == '[') && decodeJSON(body, &nested) == nil {
					return map[string]any{"encoding": "base64_json", "decoded": l.redact(nested, depth+1)}
				}
				if len(trimmed) > 4096 {
					sum := sha256.Sum256(decoded)
					return map[string]any{"omitted": "binary_base64", "bytes": len(decoded), "sha256": hex.EncodeToString(sum[:])}
				}
			}
		}
		for _, secret := range l.secrets {
			typed = strings.ReplaceAll(typed, secret, "[redacted]")
		}
		typed = sensitiveXML.ReplaceAllString(typed, "[redacted XML]")
		typed = urlUserInfo.ReplaceAllString(typed, "$1://[redacted]@")
		typed = secretQuery.ReplaceAllString(typed, "${1}[redacted]")
		typed = stokPath.ReplaceAllString(typed, "${1}[redacted]")
		if len(typed) > 256<<10 {
			sum := sha256.Sum256([]byte(typed))
			return map[string]any{"truncated": true, "bytes": len(typed), "sha256": hex.EncodeToString(sum[:]), "prefix": typed[:256<<10]}
		}
		return typed
	default:
		return value
	}
}

func decodeJSON(data []byte, value *any) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON payload")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(value)
}
