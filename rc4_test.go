package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleRC4Encrypt() {
	encrypt, err := RC4Encrypt("TrumanWong", "Hello World")
	if err != nil {
		return
	}
	fmt.Println(string(encrypt))
	// Output: b7795a2b70d9f7f80ef875
}

func TestRC4Encrypt(t *testing.T) {
	t.Run("TestRC4Encrypt", func(t *testing.T) {
		encrypt, err := RC4Encrypt("TrumanWong", "Hello World")
		assert.Equal(t, nil, err)
		assert.Equal(t, "b7795a2b70d9f7f80ef875", string(encrypt))
	})
}

func ExampleRC4Decrypt() {
	decrypt, err := RC4Decrypt("TrumanWong", "b7795a2b70d9f7f80ef875")
	if err != nil {
		return
	}
	fmt.Println(string(decrypt))
	// Output: Hello World
}

func TestRC4Decrypt(t *testing.T) {
	t.Run("TestRC4Decrypt", func(t *testing.T) {
		decrypt, err := RC4Decrypt("TrumanWong", "b7795a2b70d9f7f80ef875")
		assert.Equal(t, nil, err)
		assert.Equal(t, "Hello World", string(decrypt))
	})
}
