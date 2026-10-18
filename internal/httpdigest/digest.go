// Package httpdigest answers HTTP Digest (RFC 7616) challenges for camera
// clients using the supplied request method and URI.
package httpdigest

import (
	"crypto/md5" // Cameras require HTTP Digest MD5.
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrChallenge means a challenge was malformed or uses an unsupported option.
var ErrChallenge = errors.New("unsupported digest challenge")

// Challenge is one parsed WWW-Authenticate Digest header.
type Challenge struct {
	Realm, Nonce, Algorithm, QOP, Opaque string
	Stale                                bool
}

type nonceKey struct{ realm, nonce, algorithm string }
type nonceState struct {
	count       uint32
	clientNonce string
}

// Authorizer keeps bounded per-nonce counters so a challenge can be reused.
// It is safe for concurrent use.
type Authorizer struct {
	Username, Password string
	mu                 sync.Mutex
	nonces             map[nonceKey]*nonceState
	order              []nonceKey
}

// Header returns the Authorization value for one request.
func (a *Authorizer) Header(challenge Challenge, method, uri string) (string, error) {
	if challenge.QOP == "" {
		return header(a.Username, a.Password, method, uri, challenge, 0, ""), nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nonces == nil {
		a.nonces = make(map[nonceKey]*nonceState)
	}
	key := nonceKey{challenge.Realm, challenge.Nonce, challenge.Algorithm}
	state := a.nonces[key]
	if state == nil {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", ErrChallenge
		}
		state = &nonceState{clientNonce: hex.EncodeToString(random[:])}
		// Keep recent server nonces bounded for a continuously running service.
		if len(a.order) == 64 {
			delete(a.nonces, a.order[0])
			a.order = a.order[1:]
		}
		a.order = append(a.order, key)
		a.nonces[key] = state
	}
	if state.count == ^uint32(0) {
		return "", ErrChallenge
	}
	state.count++
	return header(a.Username, a.Password, method, uri, challenge, state.count, state.clientNonce), nil
}

// Parse reads the first Digest challenge of a WWW-Authenticate header.
func Parse(value string) (Challenge, error) {
	var result Challenge
	scheme, rest, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Digest") || !HeaderText(value) || len(value) > 8192 {
		return result, ErrChallenge
	}
	values := make(map[string]string)
	for strings.TrimSpace(rest) != "" {
		rest = strings.TrimSpace(rest)
		key, tail, found := strings.Cut(rest, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !found || key == "" {
			return result, ErrChallenge
		}
		if _, exists := values[key]; exists {
			return result, ErrChallenge
		}
		tail = strings.TrimSpace(tail)
		var item string
		if strings.HasPrefix(tail, `"`) {
			var b strings.Builder
			closed := false
			for i := 1; i < len(tail); i++ {
				if tail[i] == '\\' {
					i++
					if i == len(tail) {
						return result, ErrChallenge
					}
				} else if tail[i] == '"' {
					item = b.String()
					rest = strings.TrimSpace(tail[i+1:])
					closed = true
					break
				}
				b.WriteByte(tail[i])
			}
			if !closed || (rest != "" && !strings.HasPrefix(rest, ",")) {
				return result, ErrChallenge
			}
			rest = strings.TrimPrefix(rest, ",")
		} else {
			item, rest, _ = strings.Cut(tail, ",")
			item = strings.TrimSpace(item)
		}
		values[key] = item
	}
	result = Challenge{Realm: values["realm"], Nonce: values["nonce"], Algorithm: strings.ToUpper(values["algorithm"]), Opaque: values["opaque"]}
	result.Stale = strings.EqualFold(values["stale"], "true")
	if result.Algorithm == "" {
		result.Algorithm = "MD5"
	}
	if result.Realm == "" || result.Nonce == "" || (result.Algorithm != "MD5" && result.Algorithm != "SHA-256") || (values["charset"] != "" && !strings.EqualFold(values["charset"], "UTF-8")) || values["userhash"] == "true" {
		return result, ErrChallenge
	}
	if qop := values["qop"]; qop != "" {
		for _, option := range strings.Split(qop, ",") {
			if strings.TrimSpace(option) == "auth" {
				result.QOP = "auth"
			}
		}
		if result.QOP == "" {
			return result, ErrChallenge
		}
	}
	return result, nil
}

func header(username, password, method, uri string, c Challenge, count uint32, clientNonce string) string {
	hash := func(value string) string {
		if c.Algorithm == "SHA-256" {
			h := sha256.Sum256([]byte(value))
			return hex.EncodeToString(h[:])
		}
		h := md5.Sum([]byte(value))
		return hex.EncodeToString(h[:])
	}
	ha1, ha2 := hash(username+":"+c.Realm+":"+password), hash(method+":"+uri)
	response := hash(ha1 + ":" + c.Nonce + ":" + ha2)
	extra := ""
	if c.QOP == "auth" {
		nc := fmt.Sprintf("%08x", count)
		response = hash(ha1 + ":" + c.Nonce + ":" + nc + ":" + clientNonce + ":auth:" + ha2)
		extra = `, qop=auth, nc=` + nc + `, cnonce="` + clientNonce + `"`
	}
	quote := func(v string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) }
	if c.Opaque != "" {
		extra += `, opaque="` + quote(c.Opaque) + `"`
	}
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s"%s`, quote(username), quote(c.Realm), quote(c.Nonce), quote(uri), c.Algorithm, response, extra)
}

// HeaderText reports whether a value contains no control characters.
func HeaderText(value string) bool {
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
