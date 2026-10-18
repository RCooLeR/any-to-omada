package spakeee

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"filippo.io/edwards25519"
)

// oracleFixture holds synthetic libsodium interoperability vectors and
// Elligator mappings; it contains no captured device credentials.
type oracleFixture struct {
	Password      string `json:"password"`
	Public        string `json:"public"`
	ClientEntropy string `json:"client_entropy"`
	Response1     string `json:"response1"`
	Response2     string `json:"response2"`
	Response3     string `json:"response3"`
	ClientKey     string `json:"client_key"`
	ServerKey     string `json:"server_key"`
	Uniform       []struct {
		Input string `json:"input"`
		Point string `json:"point"`
	} `json:"uniform"`
}

func loadOracle(t *testing.T) oracleFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/libsodium_synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture oracleFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func unhex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func oracleClient(t *testing.T, fixture oracleFixture) (*Client, []byte) {
	t.Helper()
	c, response, err := newClient(unhex(t, fixture.Public), fixture.Password, bytes.NewReader(unhex(t, fixture.ClientEntropy)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Destroy)
	return c, response
}

func TestHandshakeMatchesIndependentLibsodiumOracle(t *testing.T) {
	fixture := loadOracle(t)
	c, response := oracleClient(t, fixture)
	if !bytes.Equal(response, unhex(t, fixture.Response1)) {
		t.Fatal("client share differs from libsodium oracle")
	}
	confirmation, keys, err := c.Finish(unhex(t, fixture.Response2), "VIGI-IPC", "VIGI-NVR")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(confirmation, unhex(t, fixture.Response3)) {
		t.Fatal("client confirmation differs from libsodium oracle")
	}
	if !bytes.Equal(keys.Client[:], unhex(t, fixture.ClientKey)) || !bytes.Equal(keys.Server[:], unhex(t, fixture.ServerKey)) {
		t.Fatal("session keys differ from libsodium oracle")
	}
	if _, _, err := c.Finish(unhex(t, fixture.Response2), "VIGI-IPC", "VIGI-NVR"); err == nil {
		t.Fatal("consumed exchange was accepted")
	}
}

func TestElligatorMatchesIndependentLibsodiumOracle(t *testing.T) {
	for i, vector := range loadOracle(t).Uniform {
		point, err := pointFromUniform(unhex(t, vector.Input))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(point.Bytes(), unhex(t, vector.Point)) {
			t.Fatalf("vector %d differs from libsodium oracle", i)
		}
	}
}

func TestUnauthenticatedResponseReturnsNoKeysAndConsumesState(t *testing.T) {
	fixture := loadOracle(t)
	for _, name := range []string{"confirmation", "identity", "point", "length"} {
		t.Run(name, func(t *testing.T) {
			c, _ := oracleClient(t, fixture)
			response := unhex(t, fixture.Response2)
			clientID := "VIGI-IPC"
			switch name {
			case "confirmation":
				response[63] ^= 1
			case "identity":
				clientID = "incorrect"
			case "point":
				clear(response[:32])
				response[0] = 1
			case "length":
				response = response[:63]
			}
			confirmation, keys, err := c.Finish(response, clientID, "VIGI-NVR")
			if err == nil || confirmation != nil || keys != (Keys{}) {
				t.Fatal("unauthenticated response returned keys or succeeded")
			}
			if c.hK != ([32]byte{}) || c.hL != ([32]byte{}) || !bytes.Equal(c.x.Bytes(), make([]byte, 32)) {
				t.Fatal("failed exchange retained secret state")
			}
			if _, _, err := c.Finish(unhex(t, fixture.Response2), "VIGI-IPC", "VIGI-NVR"); err == nil {
				t.Fatal("failed exchange could be reused")
			}
		})
	}
}

func TestRejectInvalidPublicParametersBeforeHashing(t *testing.T) {
	fixture := loadOracle(t)
	for _, name := range []string{"length", "version", "algorithm", "zero_work", "large_work", "zero_memory", "large_memory", "partial_kib"} {
		t.Run(name, func(t *testing.T) {
			public := unhex(t, fixture.Public)
			switch name {
			case "length":
				public = public[:35]
			case "version":
				public[0] = 2
			case "algorithm":
				public[2] = 1
			case "zero_work":
				binary.LittleEndian.PutUint64(public[4:12], 0)
			case "large_work":
				binary.LittleEndian.PutUint64(public[4:12], ^uint64(0))
			case "zero_memory":
				binary.LittleEndian.PutUint64(public[12:20], 0)
			case "large_memory":
				binary.LittleEndian.PutUint64(public[12:20], ^uint64(0))
			case "partial_kib":
				binary.LittleEndian.PutUint64(public[12:20], 8193)
			}
			if _, _, err := newClient(public, fixture.Password, bytes.NewReader(nil)); err == nil {
				t.Fatal("invalid public parameters were accepted")
			}
		})
	}
}

func TestDestroyConsumesClient(t *testing.T) {
	fixture := loadOracle(t)
	c, _ := oracleClient(t, fixture)
	c.Destroy()
	c.Destroy()
	if _, _, err := c.Finish(unhex(t, fixture.Response2), "VIGI-IPC", "VIGI-NVR"); err == nil {
		t.Fatal("destroyed client accepted a response")
	}
}

func TestZeroValueClientRejectsResponse(t *testing.T) {
	var c Client
	if _, _, err := c.Finish(make([]byte, 64), "VIGI-IPC", "VIGI-NVR"); err == nil {
		t.Fatal("uninitialized client accepted a response")
	}
}

func TestRejectNoncanonicalAndMixedOrderPoints(t *testing.T) {
	if _, err := decodePoint(edwards25519.NewGeneratorPoint().Bytes()); err != nil {
		t.Fatal("generator was rejected")
	}
	// y=0 is a nonidentity point in the small-order subgroup.
	torsion, err := new(edwards25519.Point).SetBytes(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(edwards25519.NewGeneratorPoint(), torsion)
	for _, encoded := range [][]byte{
		torsion.Bytes(),
		mixed.Bytes(),
		unhex(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		unhex(t, "0100000000000000000000000000000000000000000000000000000000000080"),
	} {
		if _, err := decodePoint(encoded); err == nil {
			t.Fatal("invalid encoding or non-prime-order point was accepted")
		}
	}
}
