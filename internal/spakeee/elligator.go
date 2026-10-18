package spakeee

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// pointFromUniform follows libsodium's ge25519_from_uniform: Elligator2 on
// Curve25519, conversion to Edwards coordinates, then cofactor clearing.
// The input's high bit selects the Edwards x sign. See NOTICE for attribution.
func pointFromUniform(uniform []byte) (*edwards25519.Point, error) {
	if len(uniform) != 32 {
		return nil, errors.New("uniform point input must contain 32 bytes")
	}
	r, err := new(field.Element).SetBytes(uniform)
	if err != nil {
		return nil, errors.New("invalid uniform field input")
	}
	one := new(field.Element).One()
	var aBytes [32]byte
	binary.LittleEndian.PutUint32(aBytes[:], 486662)
	a, err := new(field.Element).SetBytes(aBytes[:])
	if err != nil {
		return nil, errors.New("invalid curve parameter")
	}
	rr2 := new(field.Element).Square(r)
	rr2.Add(rr2, rr2)
	rr2.Add(rr2, one)
	rr2.Invert(rr2)
	x := new(field.Element).Multiply(a, rr2)
	x.Negate(x)
	x2 := new(field.Element).Square(x)
	x3 := new(field.Element).Multiply(x, x2)
	gx := new(field.Element).Add(x3, x)
	x2.Multiply(a, x2)
	gx.Add(gx, x2)
	_, square := new(field.Element).SqrtRatio(gx, one)
	alternative := new(field.Element).Negate(x)
	alternative.Subtract(alternative, a)
	x.Select(x, alternative, square)
	numerator := new(field.Element).Subtract(x, one)
	denominator := new(field.Element).Add(x, one)
	denominator.Invert(denominator)
	y := new(field.Element).Multiply(numerator, denominator)
	encoded := y.Bytes()
	encoded[31] |= uniform[31] & 0x80
	p, err := new(edwards25519.Point).SetBytes(encoded)
	if err != nil {
		return nil, errors.New("elligator mapping produced an invalid point")
	}
	return new(edwards25519.Point).MultByCofactor(p), nil
}

func decodePoint(encoded []byte) (*edwards25519.Point, error) {
	p, err := new(edwards25519.Point).SetBytes(encoded)
	if err != nil || subtle.ConstantTimeCompare(p.Bytes(), encoded) != 1 {
		return nil, errors.New("spakeee invalid server point encoding")
	}
	if !primeOrderPoint(p) {
		return nil, errors.New("spakeee invalid server point group")
	}
	return p, nil
}

func primeOrderPoint(p *edwards25519.Point) bool {
	// Project into the prime-order subgroup with [1/8]([8]P). Comparing
	// against P rejects mixed-order points as well as the small-order group.
	cofactored := new(edwards25519.Point).MultByCofactor(p)
	if cofactored.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	var eightBytes [32]byte
	eightBytes[0] = 8
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(eightBytes[:])
	if err != nil {
		return false
	}
	inverse := new(edwards25519.Scalar).Invert(eight)
	projected := new(edwards25519.Point).ScalarMult(inverse, cofactored)
	return projected.Equal(p) == 1
}
