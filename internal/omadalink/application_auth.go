package omadalink

import (
	"crypto/md5" // The observed native callback account protocol requires MD5.
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const applicationAuthAttempts = 5

// ApplicationCredentials holds a derived account verifier, not the plaintext
// password or the unrelated callback registration auth_code. It is immutable.
type ApplicationCredentials struct {
	username string
	ha1      string
}

// NewApplicationCredentials derives the native account verifier. The firmware
// applies its legacy XOR lookup transform before MD5(username:realm:password),
// unlike the HTTPS login proof. This function has no device or logging effects.
func NewApplicationCredentials(username, password string) (*ApplicationCredentials, error) {
	if username == "" || len(username) > 128 || password == "" || len(password) > 1024 || strings.ContainsRune(username+password, 0) {
		return nil, errors.New("invalid native callback account")
	}
	return &ApplicationCredentials{username: username, ha1: applicationMD5(username + ":vigi:" + applicationPassword(password))}, nil
}

// ApplicationAuth owns account authentication for one already secured callback
// connection. It is not concurrency-safe. A new connection needs a new instance.
type ApplicationAuth struct {
	credentials   *ApplicationCredentials
	random        io.Reader
	nonce         string
	nonceCount    uint32
	failures      int
	authenticated bool
}

// NewApplicationAuth creates unauthenticated connection state. Credentials must
// come from NewApplicationCredentials; no plaintext password is retained.
func NewApplicationAuth(credentials *ApplicationCredentials) (*ApplicationAuth, error) {
	if credentials == nil || credentials.username == "" || len(credentials.ha1) != 32 {
		return nil, errors.New("native callback account is not configured")
	}
	return &ApplicationAuth{credentials: credentials, random: rand.Reader}, nil
}

// Authenticated reports account-proof verification, distinct from PAKE/TLS.
func (a *ApplicationAuth) Authenticated() bool { return a.authenticated }

// Challenge returns the captured outer -40401 response to an unauthenticated
// passthrough. Its time/max_time fields count remaining attempts, not seconds.
func (a *ApplicationAuth) Challenge(id uint16) ([]byte, error) {
	return a.challenge(id, -40401)
}

// challenge rotates the connection nonce and increments its count while keeping
// the remaining-attempt budget separate from the protocol response code.
func (a *ApplicationAuth) challenge(id uint16, code int) ([]byte, error) {
	if a.failures >= applicationAuthAttempts {
		return nil, errors.New("native callback account attempts exhausted")
	}
	var nonce [16]byte
	if _, err := io.ReadFull(a.random, nonce[:]); err != nil {
		return nil, errors.New("native callback challenge generation failed")
	}
	a.nonce = hex.EncodeToString(nonce[:])
	a.nonceCount++
	return encodeAccountResponse(id, code, struct {
		Realm     string `json:"realm"`
		Algorithm string `json:"algorithm"`
		QOP       string `json:"qop"`
		Nonce     string `json:"nonce"`
		NC        string `json:"nc"`
		URI       string `json:"uri"`
		Time      int    `json:"time"`
		MaxTime   int    `json:"max_time"`
	}{"vigi", "digestmd5", "auth", a.nonce, strconv.FormatUint(uint64(a.nonceCount), 10), "tplink", applicationAuthAttempts - a.failures, applicationAuthAttempts})
}

// Authenticate verifies the captured object-shaped Auth request and returns a
// correlated Response. A wrong proof renews the challenge with outer -40407.
// It never echoes malformed fields or exposes account material in errors.
func (a *ApplicationAuth) Authenticate(id uint16, request json.RawMessage) ([]byte, bool, error) {
	var proof struct {
		Username  string `json:"username"`
		Realm     string `json:"realm"`
		Nonce     string `json:"nonce"`
		URI       string `json:"uri"`
		Response  string `json:"response"`
		QOP       string `json:"qop"`
		NC        string `json:"nc"`
		CNonce    string `json:"cnonce"`
		Algorithm string `json:"algorithm"`
	}
	valid := len(request) <= MaxApplicationFrameSize && json.Unmarshal(request, &proof) == nil
	valid = valid && !a.authenticated && a.nonce != "" && proof.Realm == "vigi" && proof.URI == "tplink" && proof.QOP == "auth" &&
		(proof.Algorithm == "" || proof.Algorithm == "digestmd5") && proof.NC == strconv.FormatUint(uint64(a.nonceCount), 10) &&
		len(proof.CNonce) > 0 && len(proof.CNonce) <= 128 && !strings.ContainsRune(proof.CNonce, 0)
	valid = valid && subtle.ConstantTimeCompare([]byte(proof.Username), []byte(a.credentials.username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(proof.Nonce), []byte(a.nonce)) == 1 &&
		subtle.ConstantTimeCompare([]byte(proof.Response), []byte(applicationDigest(a.credentials.ha1, a.nonce, proof.NC))) == 1
	if !valid {
		a.authenticated = false
		a.failures++
		frame, err := a.challenge(id, -40407)
		return frame, false, err
	}
	a.authenticated = true
	a.nonce = "" // A proof belongs to one challenge on one callback connection.
	frame, err := encodeAccountResponse(id, 0, struct {
		Username string `json:"username"`
		Realm    string `json:"realm"`
		URI      string `json:"uri"`
		RespAuth string `json:"respauth"`
		QOP      string `json:"qop"`
		NC       string `json:"nc"`
		CNonce   string `json:"cnonce"`
	}{a.credentials.username, "vigi", "tplink", applicationDigest(a.credentials.ha1, proof.CNonce, proof.NC), "auth", proof.NC, proof.CNonce})
	return frame, err == nil, err
}

// applicationDigest passes the server nonce in both Digest nonce
// positions for request verification, and the client nonce in both positions
// for respauth. The method is the literal digestmd5, not an HTTP method. These
// argument positions are established by the donor's 0x3b1ae8-0x3b1bf8 calls.
func applicationDigest(ha1, nonce, count string) string {
	return applicationMD5(ha1 + ":" + nonce + ":" + count + ":" + nonce + ":auth:" + applicationMD5("digestmd5:tplink"))
}

// applicationMD5 returns the lowercase hex digest required by callback account
// authentication; it is not a general-purpose password hash.
func applicationMD5(value string) string {
	hash := md5.Sum([]byte(value))
	return hex.EncodeToString(hash[:])
}

// applicationPassword reproduces the firmware's XOR/lookup password transform
// before account-verifier derivation; it does not encrypt stored credentials.
func applicationPassword(password string) string {
	// Public protocol constants from donor helper 0x250328 and the NVR web
	// client's password transform; neither constant is a device secret.
	const salt = "RDpbLfCPsJZ7fiv"
	const alphabet = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
	result := make([]byte, max(len(password), len(salt)))
	for i := range result {
		left, right := byte(187), byte(187)
		if i < len(password) {
			left = password[i]
		}
		if i < len(salt) {
			right = salt[i]
		}
		result[i] = alphabet[int(left^right)%len(alphabet)]
	}
	return string(result)
}

// encodeAccountResponse wraps account-authentication data in a size-bounded
// Response envelope, preserving the recorder-owned correlation ID.
func encodeAccountResponse(id uint16, code int, data any) ([]byte, error) {
	body, err := json.Marshal(struct {
		ResponseData any    `json:"responseData"`
		ID           uint16 `json:"id"`
		ErrorCode    int    `json:"error_code"`
	}{data, id, code})
	if err != nil {
		return nil, ErrInvalidFrame
	}
	header := startBoundary + "Content-Type:Response\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n"
	if len(header)+len(body)+len(endBoundary) > MaxPostTLSFrameSize {
		return nil, ErrFrameTooLarge
	}
	return []byte(header + string(body) + endBoundary), nil
}
