package httpdigest

import (
	"crypto/md5"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestParseAcceptsCameraChallengesAndRejectsUnsupportedOnes(t *testing.T) {
	challenge, err := Parse(`Digest realm="IP Camera(C1234)", nonce="abc", qop="auth,auth-int", opaque="o", stale=TRUE`)
	if err != nil || challenge.Realm != "IP Camera(C1234)" || challenge.QOP != "auth" || challenge.Algorithm != "MD5" || !challenge.Stale || challenge.Opaque != "o" {
		t.Fatalf("challenge = %+v, %v", challenge, err)
	}
	for _, header := range []string{
		`Basic realm="x"`,
		`Digest realm="x"`,
		`Digest realm="x", nonce="n", algorithm=SHA-512`,
		`Digest realm="x", nonce="n", qop="auth-int"`,
		`Digest realm="x", nonce="n", realm="y"`,
		"Digest realm=\"x\nInjected: 1\", nonce=\"n\"",
	} {
		if _, err := Parse(header); err == nil {
			t.Fatalf("accepted %q", header)
		}
	}
}

func TestHeaderComputesRFC7616ResponseWithIncreasingCount(t *testing.T) {
	authorizer := &Authorizer{Username: "admin", Password: "secret"}
	challenge := Challenge{Realm: "cam", Nonce: "n1", Algorithm: "MD5", QOP: "auth"}
	hash := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
	for want := 1; want <= 2; want++ {
		value, err := authorizer.Header(challenge, "GET", "/ISAPI/Event/notification/alertStream")
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{}
		for _, match := range regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^, ]+))`).FindAllStringSubmatch(value, -1) {
			fields[match[1]] = match[2] + match[3]
		}
		if !strings.Contains(value, "algorithm=MD5,") || !strings.Contains(value, ", qop=auth,") || !strings.Contains(value, ", nc=0000000") {
			t.Fatalf("Digest token fields must not be quoted: %s", value)
		}
		expected := hash(hash("admin:cam:secret") + ":n1:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + hash("GET:/ISAPI/Event/notification/alertStream"))
		if fields["response"] != expected || fields["nc"] != []string{"", "00000001", "00000002"}[want] || strings.Contains(value, "secret") {
			t.Fatalf("header %d = %s", want, value)
		}
	}
}
