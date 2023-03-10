package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRC4Encrypt(t *testing.T) {
	t.Run("TestRC4Encrypt", func(t *testing.T) {
		encrypt, err := RC4Encrypt("TrumanWong", "Hello World")
		assert.Equal(t, nil, err)
		assert.Equal(t, "b7795a2b70d9f7f80ef875", string(encrypt))
	})
}

func TestRC4Decrypt(t *testing.T) {
	t.Run("TestRC4Decrypt", func(t *testing.T) {
		decrypt, err := RC4Decrypt("TrumanWong", "b7795a2b70d9f7f80ef875")
		assert.Equal(t, nil, err)
		assert.Equal(t, "Hello World", string(decrypt))
	})
}
