package omadalink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// These synthetic vectors were calculated independently with Python hashlib
// and constants read from the donor helper, for passwords shorter/longer than
// the 15-byte salt. No captured account, nonce or authentication proof is used.
func TestApplicationAccountIndependentVectors(t *testing.T) {
	for _, test := range []struct{ password, transformed, ha1, proof, respauth string }{
		{"synthetic-password", "7P3t3V3dRW8gdTLCYy", "d0b9e2378c49cee5509784ee7d6e86ef", "3192594a9770e61ee387efee62fbb61d", "f1ff68751b078f36b029f071e23876a5"},
		{"short", "7pHRobhc9TefbwK", "17704457990ea287a1e1d5d8009e0728", "ffd3680de4607927910cf64d5ad05764", "d510e017b0f0a1bc6770dcc7329c4015"},
	} {
		t.Run(test.password, func(t *testing.T) {
			credentials, err := NewApplicationCredentials("fixture-user", test.password)
			if err != nil || credentials.ha1 != test.ha1 || applicationPassword(test.password) != test.transformed {
				t.Fatal("independent password verifier vector mismatch")
			}
			auth, err := NewApplicationAuth(credentials)
			if err != nil {
				t.Fatal(err)
			}
			auth.random = bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
			challenge, err := auth.Challenge(11)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(challenge)))
			if err != nil || frame.ContentType != ApplicationResponse {
				t.Fatal("invalid challenge framing")
			}
			var c struct {
				ID        uint16         `json:"id"`
				ErrorCode int            `json:"error_code"`
				Data      map[string]any `json:"responseData"`
			}
			if json.Unmarshal(frame.Body, &c) != nil || c.ID != 11 || c.ErrorCode != -40401 || c.Data["nonce"] != "000102030405060708090a0b0c0d0e0f" || c.Data["nc"] != "1" || c.Data["time"] != float64(5) {
				t.Fatal("challenge contract mismatch")
			}
			request := `{"username":"fixture-user","realm":"vigi","nonce":"000102030405060708090a0b0c0d0e0f","uri":"tplink","qop":"auth","nc":"1","cnonce":"synthetic-client-nonce","algorithm":"digestmd5","time":5,"max_time":5,"response":"` + test.proof + `"}`
			reply, ok, err := auth.Authenticate(12, []byte(request))
			if err != nil || !ok || !auth.Authenticated() {
				t.Fatal("independent request proof rejected")
			}
			frame, err = ReadApplicationFrame(bufio.NewReader(bytes.NewReader(reply)))
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				ID        uint16 `json:"id"`
				ErrorCode int    `json:"error_code"`
				Data      struct {
					RespAuth string `json:"respauth"`
					CNonce   string `json:"cnonce"`
				} `json:"responseData"`
			}
			if json.Unmarshal(frame.Body, &response) != nil || response.ID != 12 || response.ErrorCode != 0 || response.Data.RespAuth != test.respauth || response.Data.CNonce != "synthetic-client-nonce" {
				t.Fatal("independent reciprocal proof mismatch")
			}
		})
	}
}

func TestApplicationAccountRejectsWrongProofReplayAndMalformedFields(t *testing.T) {
	valid := `{"username":"fixture-user","realm":"vigi","nonce":"000102030405060708090a0b0c0d0e0f","uri":"tplink","qop":"auth","nc":"1","cnonce":"synthetic-client-nonce","response":"3192594a9770e61ee387efee62fbb61d"}`
	for name, request := range map[string]string{
		"wrong proof":          strings.Replace(valid, "3192594a9770e61ee387efee62fbb61d", strings.Repeat("0", 32), 1),
		"wrong username":       strings.Replace(valid, "fixture-user", "other-user", 1),
		"wrong nonce":          strings.Replace(valid, "000102030405060708090a0b0c0d0e0f", strings.Repeat("0", 32), 1),
		"wrong count":          strings.Replace(valid, `"nc":"1"`, `"nc":"2"`, 1),
		"wrong realm":          strings.Replace(valid, `"vigi"`, `"other"`, 1),
		"missing client nonce": strings.Replace(valid, `"cnonce":"synthetic-client-nonce",`, "", 1),
		"wrong type":           strings.Replace(valid, `"nc":"1"`, `"nc":1`, 1),
		"array":                "[]",
		"null":                 "null",
	} {
		t.Run(name, func(t *testing.T) {
			credentials, _ := NewApplicationCredentials("fixture-user", "synthetic-password")
			auth, _ := NewApplicationAuth(credentials)
			auth.random = bytes.NewReader(append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, bytes.Repeat([]byte{42}, 32)...))
			if _, err := auth.Challenge(1); err != nil {
				t.Fatal(err)
			}
			response, accepted, err := auth.Authenticate(2, []byte(request))
			if err != nil || accepted || auth.Authenticated() {
				t.Fatal("invalid proof accepted or retry unavailable")
			}
			frame, err := ReadApplicationFrame(bufio.NewReader(bytes.NewReader(response)))
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				ErrorCode int `json:"error_code"`
				Data      struct {
					NC   string `json:"nc"`
					Time int    `json:"time"`
				} `json:"responseData"`
			}
			if json.Unmarshal(frame.Body, &decoded) != nil || decoded.ErrorCode != -40407 || decoded.Data.NC != "2" || decoded.Data.Time != 4 {
				t.Fatal("wrong proof did not renew bounded challenge")
			}
			if _, accepted, err := auth.Authenticate(3, []byte(valid)); err != nil || accepted {
				t.Fatal("earlier nonce proof was replayed")
			}
		})
	}
}

func TestApplicationAccountFailureBoundAndFraming(t *testing.T) {
	credentials, _ := NewApplicationCredentials("fixture-user", "synthetic-password")
	auth, _ := NewApplicationAuth(credentials)
	for i := range applicationAuthAttempts {
		_, ok, err := auth.Authenticate(uint16(i+1), []byte(`{"response":"untrusted-private-value"}`))
		if ok || (i == applicationAuthAttempts-1) != (err != nil) {
			t.Fatal("failure bound mismatch")
		}
		if err != nil && strings.Contains(err.Error(), "untrusted") {
			t.Fatal("private value in error")
		}
	}
	body := `{"id":2,"method":"auth","requestData":{}}`
	wire := startBoundary + "Content-Type:Auth\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n" + body + endBoundary + "\r\n"
	frame, err := ReadApplicationFrame(bufio.NewReader(strings.NewReader(wire)))
	if err != nil || frame.ContentType != ApplicationAuthRequest {
		t.Fatalf("captured Auth content type rejected: %v", err)
	}
	if _, err := NewApplicationAuth(nil); err == nil {
		t.Fatal("missing account accepted")
	}
}
