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

type PublicKey struct {
	N *big.Int
	g *big.Int // this is just n+1, do we need it?
}

type PrivateKey struct {
	lm *big.Int
	mu *big.Int
}

type Keypair struct {
	*PrivateKey
	*PublicKey
}

func GenerateKeypair(bits int) (*Keypair, error) {
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

	return &Keypair{
		PublicKey: &PublicKey{
			N: n,
			g: g,
		},
		PrivateKey: &PrivateKey{
			lm: lm,
			mu: mu,
		},
	}, nil
}

type Ciphertext struct {
	c *big.Int
}

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
