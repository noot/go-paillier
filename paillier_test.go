package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	kp, err := GeneratePrivateKey(1024)
	require.NoError(t, err)

	m, err := rand.Int(rand.Reader, kp.N)
	require.NoError(t, err)
	c, err := kp.Encrypt(m)
	require.NoError(t, err)

	res := kp.Decrypt(c)
	require.NoError(t, err)
	require.Equal(t, m, res)
}

func TestEncryptionHomomorphic(t *testing.T) {
	kp, err := GeneratePrivateKey(1024)
	require.NoError(t, err)

	m1, err := rand.Int(rand.Reader, kp.N)
	require.NoError(t, err)
	c1, err := kp.Encrypt(m1)
	require.NoError(t, err)

	m2, err := rand.Int(rand.Reader, kp.N)
	require.NoError(t, err)
	c2, err := kp.Encrypt(m2)
	require.NoError(t, err)

	n2 := (&big.Int{}).Mul(kp.N, kp.N)
	cProd := (&big.Int{}).Mul(c1.c, c2.c)
	cProd = (&big.Int{}).Mod(cProd, n2)

	mSum := (&big.Int{}).Add(m1, m2)
	mSum = (&big.Int{}).Mod(mSum, kp.N)

	res := kp.Decrypt(&Ciphertext{cProd})
	require.NoError(t, err)
	require.Equal(t, mSum, res)
}
