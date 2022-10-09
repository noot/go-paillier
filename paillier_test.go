package paillier

import (
	"crypto/rand"
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
