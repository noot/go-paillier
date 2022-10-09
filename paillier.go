package paillier

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	one = big.NewInt(1)

	errMessageTooLarge = errors.New("message must be smaller than PublicKey.N")
	errNegativeMessage = errors.New("message cannot be less than zero")
)

// PublicKey represents a Paillier public (encryption) key.
type PublicKey struct {
	N *big.Int
	g *big.Int // this is just n+1, do we need it?
}

// PrivateKey represents a Paillier secret (decryption) key.
type PrivateKey struct {
	*PublicKey
	lm *big.Int
	mu *big.Int
}

// GeneratePrivateKey generates a new PrivateKey with an embedded PublicKey.
// The `bits` parameter corresponds to the size of n^2.
func GeneratePrivateKey(bits int) (*PrivateKey, error) {
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}

	n := (&big.Int{}).Mul(p, q)
	g := (&big.Int{}).Add(n, one)

	p1 := (&big.Int{}).Sub(p, one)
	q1 := (&big.Int{}).Sub(q, one)
	lm := (&big.Int{}).Mul(p1, q1)

	mu := (&big.Int{}).ModInverse(lm, n)

	pk := &PublicKey{
		N: n,
		g: g,
	}

	return &PrivateKey{
		PublicKey: pk,
		lm:        lm,
		mu:        mu,
	}, nil
}

// Ciphertext represents a Paillier ciphertext.
type Ciphertext struct {
	c *big.Int
}

// Encrypt encrypts the plaintext message with the given public key.
func (pk *PublicKey) Encrypt(m *big.Int) (*Ciphertext, error) {
	// require 0 <= m < n
	if m.Cmp(pk.N) > 0 {
		return nil, errMessageTooLarge
	}

	if m.Cmp(big.NewInt(0)) < 0 {
		return nil, errNegativeMessage
	}

	// pick random 0 < r < n
	r, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		return nil, err
	}

	n2 := (&big.Int{}).Mul(pk.N, pk.N)

	gm := (&big.Int{}).Exp(pk.g, m, n2)
	rn := (&big.Int{}).Exp(r, pk.N, n2)
	c := (&big.Int{}).Mul(gm, rn)
	c = (&big.Int{}).Mod(c, n2)
	return &Ciphertext{
		c: c,
	}, nil
}

// Decrypt returns the plaintext decrypted from the ciphertext using the
// given secret key.
func (sk *PrivateKey) Decrypt(c *Ciphertext) *big.Int {
	n2 := (&big.Int{}).Mul(sk.N, sk.N)

	// c^lambda mod n^2
	clm := (&big.Int{}).Exp(c.c, sk.lm, n2)

	// L(c^lambda mod n^2)
	// where L(x) = (x-1)/n
	l := (&big.Int{}).Sub(clm, one)
	l = (&big.Int{}).Div(l, sk.N)

	// L(c^lambda mod n^2) * mu mod n
	m := (&big.Int{}).Mul(l, sk.mu)
	m = (&big.Int{}).Mod(m, sk.N)
	return m
}
