// Package spakeee implements the SPAKE2+ Elligator Edition client used by the
// recorder's native callback. It is separate from HTTP SPAKE2+ authentication.
// The protocol follows jedisct1/spake2-ee; see NOTICE for attribution.
package spakeee

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"filippo.io/edwards25519"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/argon2"
)

const (
	publicDataSize = 36
	maxIterations  = 4
	maxMemoryBytes = 16 * 1024 * 1024
)

// Keys contains the two authenticated session keys in the upstream protocol's
// client/server order. Neither key may be used before Finish succeeds.
type Keys struct {
	Client [32]byte
	Server [32]byte
}

// Client holds one exchange. Finish consumes it even on failure. Its methods
// synchronize state access; Destroy releases state when a transport aborts.
type Client struct {
	// mu guards the single-use exchange state, including key derivation and clearing.
	mu     sync.Mutex
	ready  bool
	used   bool
	x      edwards25519.Scalar
	n      edwards25519.Point
	public [32]byte
	hK     [32]byte
	hL     [32]byte
}

// NewClient processes the recorder's 36-byte public parameters and produces its
// 32-byte client share. The password is the fresh callback auth_code, not the
// camera account password. Argon2id work is bounded before allocating memory.
func NewClient(publicData []byte, password string) (*Client, []byte, error) {
	return newClient(publicData, password, rand.Reader)
}

// newClient initializes one bounded PAKE exchange using the supplied entropy reader;
// password-derived temporary buffers are cleared before returning.
func newClient(publicData []byte, password string, random io.Reader) (*Client, []byte, error) {
	iterations, memoryKiB, err := parameters(publicData)
	if err != nil {
		return nil, nil, err
	}
	if len(password) > 4096 {
		return nil, nil, errors.New("spakeee password exceeds supported length")
	}
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	material := argon2.IDKey(passwordBytes, publicData[20:36], iterations, memoryKiB, 1, 128)
	defer clear(material)
	m, err := pointFromUniform(material[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("spakeee map client mask: %w", err)
	}
	n, err := pointFromUniform(material[32:64])
	if err != nil {
		return nil, nil, fmt.Errorf("spakeee map server mask: %w", err)
	}
	x, err := randomScalar(random)
	if err != nil {
		return nil, nil, fmt.Errorf("spakeee generate scalar: %w", err)
	}
	defer func() { *x = edwards25519.Scalar{} }()
	public := new(edwards25519.Point).ScalarBaseMult(x)
	public.Add(public, m)
	c := &Client{ready: true, x: *x, n: *n}
	copy(c.public[:], public.Bytes())
	copy(c.hK[:], material[64:96])
	copy(c.hL[:], material[96:128])
	return c, append([]byte(nil), c.public[:]...), nil
}

// parameters validates the advertised Argon2id parameters before allocation and
// returns iterations and memory in KiB, converting the wire byte count.
func parameters(publicData []byte) (uint32, uint32, error) {
	if len(publicData) != publicDataSize {
		return 0, 0, errors.New("spakeee public parameters must contain 36 bytes")
	}
	if binary.LittleEndian.Uint16(publicData[:2]) != 1 || binary.LittleEndian.Uint16(publicData[2:4]) != 2 {
		return 0, 0, errors.New("spakeee unsupported parameter version or algorithm")
	}
	iterations := binary.LittleEndian.Uint64(publicData[4:12])
	memory := binary.LittleEndian.Uint64(publicData[12:20])
	if iterations == 0 || iterations > maxIterations || memory < 8192 || memory > maxMemoryBytes || memory%1024 != 0 {
		return 0, 0, errors.New("spakeee password hashing parameters exceed supported bounds")
	}
	return uint32(iterations), uint32(memory / 1024), nil
}

// randomScalar draws a nonzero scalar with the protocol's unclamped bit mask;
// repeated zero entropy is rejected after sixteen attempts.
func randomScalar(random io.Reader) (*edwards25519.Scalar, error) {
	var wide [64]byte
	defer clear(wide[:])
	for attempt := 0; attempt < 16; attempt++ {
		if _, err := io.ReadFull(random, wide[:32]); err != nil {
			return nil, err
		}
		// The protocol clears these bits but does not set bit 254. Its public
		// share uses libsodium's base_noclamp operation.
		wide[0] &= 248
		wide[31] &= 127
		var nonzero byte
		for _, b := range wide[:32] {
			nonzero |= b
		}
		if nonzero != 0 {
			return new(edwards25519.Scalar).SetUniformBytes(wide[:])
		}
	}
	return nil, errors.New("random source repeatedly produced zero scalars")
}

// Finish authenticates the 64-byte server response and returns the 32-byte
// confirmation plus session keys. IDs are exact protocol bytes, normally
// "VIGI-IPC" and "VIGI-NVR". A failed confirmation never returns derived keys.
func (c *Client) Finish(response []byte, clientID, serverID string) ([]byte, Keys, error) {
	if c == nil {
		return nil, Keys{}, errors.New("spakeee client is unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready || c.used {
		return nil, Keys{}, errors.New("spakeee exchange already consumed")
	}
	c.used = true
	defer c.clearState()
	if len(response) != 64 || len(clientID) > 255 || len(serverID) > 255 {
		return nil, Keys{}, errors.New("spakeee invalid response or identity length")
	}
	y, err := decodePoint(response[:32])
	if err != nil {
		return nil, Keys{}, err
	}
	gy := new(edwards25519.Point).Subtract(y, &c.n)
	if !primeOrderPoint(gy) {
		return nil, Keys{}, errors.New("spakeee invalid unmasked server point")
	}
	z := new(edwards25519.Point).ScalarMult(&c.x, gy)
	hL, err := new(edwards25519.Scalar).SetBytesWithClamping(c.hL[:])
	if err != nil {
		return nil, Keys{}, errors.New("spakeee invalid password scalar")
	}
	defer func() { *hL = edwards25519.Scalar{} }()
	v := new(edwards25519.Point).ScalarMult(hL, gy)
	if z.Equal(edwards25519.NewIdentityPoint()) == 1 || v.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, Keys{}, errors.New("spakeee invalid shared point")
	}
	keys, expected, confirmation, err := deriveKeys(clientID, serverID, c.public[:], response[:32], z.Bytes(), c.hK[:], v.Bytes())
	defer clear(expected[:])
	if err != nil {
		return nil, Keys{}, err
	}
	if subtle.ConstantTimeCompare(response[32:], expected[:]) != 1 {
		clear(keys.Client[:])
		clear(keys.Server[:])
		clear(confirmation[:])
		return nil, Keys{}, errors.New("spakeee server confirmation failed")
	}
	return confirmation[:], keys, nil
}

// deriveKeys binds the exact identities and exchanged points into the BLAKE2b
// transcript, deriving directional keys and server/client confirmations.
func deriveKeys(clientID, serverID string, x, y, z, hK, v []byte) (Keys, [32]byte, [32]byte, error) {
	transcript := make([]byte, 0, 3+len(clientID)+len(serverID)+160)
	transcript = append(transcript, 1, byte(len(clientID)))
	transcript = append(transcript, clientID...)
	transcript = append(transcript, byte(len(serverID)))
	transcript = append(transcript, serverID...)
	for _, value := range [][]byte{x, y, z, hK, v} {
		transcript = append(transcript, value...)
	}
	defer clear(transcript)
	k0 := blake2b.Sum256(transcript)
	defer clear(k0[:])
	var derived [4][32]byte
	defer func() {
		for i := range derived {
			clear(derived[i][:])
		}
	}()
	for i := range derived {
		var salt [16]byte
		binary.LittleEndian.PutUint64(salt[:], uint64(i))
		h, err := blake2b.New(&blake2b.Config{Size: 32, Key: k0[:], Salt: salt[:], Person: []byte("PAKE2+EE")})
		if err != nil {
			return Keys{}, [32]byte{}, [32]byte{}, errors.New("spakeee initialize key derivation")
		}
		copy(derived[i][:], h.Sum(nil))
	}
	return Keys{Client: derived[0], Server: derived[1]}, derived[2], derived[3], nil
}

// Destroy consumes the exchange and clears its retained password-derived and
// ephemeral state. It is safe to call after Finish or more than once.
func (c *Client) Destroy() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.used = true
	c.clearState()
}

// clearState clears retained exchange material; the caller must hold c.mu.
func (c *Client) clearState() {
	c.ready = false
	c.x = edwards25519.Scalar{}
	c.n = *edwards25519.NewIdentityPoint()
	clear(c.public[:])
	clear(c.hK[:])
	clear(c.hL[:])
}
