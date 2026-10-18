package onvifptz

import (
	"crypto/md5" // ONVIF cameras may require HTTP Digest MD5.
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// The request URI is a parameter because a camera serves PTZ and media on
// separate service paths.

// digestChallenge contains the supported, validated HTTP Digest parameters
// returned by the camera, including its explicit stale-nonce signal.
type digestChallenge struct {
	realm, nonce, algorithm, qop, opaque string
	stale                                bool
}

// digestNonceKey scopes counters to one server nonce, realm and hash algorithm.
type digestNonceKey struct{ realm, nonce, algorithm string }

// digestNonceState retains a client nonce and increasing request count for qop=auth.
type digestNonceState struct {
	count       uint32
	clientNonce string
}

// authorization signs a service URI and advances qop nonce state under authMu.
// The cache retains at most 64 server nonces and refuses counter rollover.
func (c *soapClient) authorization(challenge digestChallenge, uri string) (string, error) {
	if challenge.qop == "" {
		return digestHeader(c.username, c.password, uri, challenge, 0, ""), nil
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.nonces == nil {
		c.nonces = make(map[digestNonceKey]*digestNonceState)
	}
	key := digestNonceKey{challenge.realm, challenge.nonce, challenge.algorithm}
	state := c.nonces[key]
	if state == nil {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", ErrAuthentication
		}
		state = &digestNonceState{clientNonce: hex.EncodeToString(random[:])}
		// Keep recent server nonces bounded for a continuously running service.
		if len(c.nonceOrder) == 64 {
			delete(c.nonces, c.nonceOrder[0])
			c.nonceOrder = c.nonceOrder[1:]
		}
		c.nonceOrder = append(c.nonceOrder, key)
		c.nonces[key] = state
	}
	if state.count == ^uint32(0) {
		return "", ErrAuthentication
	}
	state.count++
	return digestHeader(c.username, c.password, uri, challenge, state.count, state.clientNonce), nil
}

// parseDigest accepts bounded MD5/SHA-256 challenges with absent qop or auth;
// duplicate fields, malformed quoting and unsupported modes are rejected.
func parseDigest(header string) (digestChallenge, error) {
	var result digestChallenge
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Digest") || !headerText(header) || len(header) > 8192 {
		return result, ErrAuthentication
	}
	values := make(map[string]string)
	for strings.TrimSpace(rest) != "" {
		rest = strings.TrimSpace(rest)
		key, tail, found := strings.Cut(rest, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !found || key == "" {
			return result, ErrAuthentication
		}
		if _, exists := values[key]; exists {
			return result, ErrAuthentication
		}
		tail = strings.TrimSpace(tail)
		var value string
		if strings.HasPrefix(tail, `"`) {
			var b strings.Builder
			closed := false
			for i := 1; i < len(tail); i++ {
				if tail[i] == '\\' {
					i++
					if i == len(tail) {
						return result, ErrAuthentication
					}
				} else if tail[i] == '"' {
					value = b.String()
					rest = strings.TrimSpace(tail[i+1:])
					closed = true
					break
				}
				b.WriteByte(tail[i])
			}
			if !closed || (rest != "" && !strings.HasPrefix(rest, ",")) {
				return result, ErrAuthentication
			}
			rest = strings.TrimPrefix(rest, ",")
		} else {
			value, rest, _ = strings.Cut(tail, ",")
			value = strings.TrimSpace(value)
		}
		values[key] = value
	}
	result = digestChallenge{realm: values["realm"], nonce: values["nonce"], algorithm: strings.ToUpper(values["algorithm"]), opaque: values["opaque"]}
	result.stale = strings.EqualFold(values["stale"], "true")
	if result.algorithm == "" {
		result.algorithm = "MD5"
	}
	if result.realm == "" || result.nonce == "" || (result.algorithm != "MD5" && result.algorithm != "SHA-256") || (values["charset"] != "" && !strings.EqualFold(values["charset"], "UTF-8")) || values["userhash"] == "true" {
		return result, ErrAuthentication
	}
	if qop := values["qop"]; qop != "" {
		for _, option := range strings.Split(qop, ",") {
			if strings.TrimSpace(option) == "auth" {
				result.qop = "auth"
			}
		}
		if result.qop == "" {
			return result, ErrAuthentication
		}
	}
	return result, nil
}

// digestHeader signs a SOAP POST using validated challenge fields. The camera
// compatibility form quotes qop, nonce count and algorithm as well as strings.
func digestHeader(username, password, uri string, c digestChallenge, count uint32, clientNonce string) string {
	hash := func(value string) string {
		if c.algorithm == "SHA-256" {
			h := sha256.Sum256([]byte(value))
			return hex.EncodeToString(h[:])
		}
		h := md5.Sum([]byte(value))
		return hex.EncodeToString(h[:])
	}
	ha1, ha2 := hash(username+":"+c.realm+":"+password), hash("POST:"+uri)
	response := hash(ha1 + ":" + c.nonce + ":" + ha2)
	extra := ""
	if c.qop == "auth" {
		nc := fmt.Sprintf("%08x", count)
		response = hash(ha1 + ":" + c.nonce + ":" + nc + ":" + clientNonce + ":auth:" + ha2)
		extra = `, qop="auth", nc="` + nc + `", cnonce="` + clientNonce + `"`
	}
	quote := func(v string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) }
	if c.opaque != "" {
		extra += `, opaque="` + quote(c.opaque) + `"`
	}
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm="%s", response="%s"%s`, quote(username), quote(c.realm), quote(c.nonce), uri, c.algorithm, response, extra)
}

// headerText rejects control characters before values enter authentication headers.
func headerText(value string) bool {
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
