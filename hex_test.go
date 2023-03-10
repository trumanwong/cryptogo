package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHexEncode(t *testing.T) {
	assert.Equal(t, "48656c6c6f20576f726c64", string(HexEncode([]byte("Hello World"))))
}

func TestHexDecode(t *testing.T) {
	t.Run("Test Hex Decode", func(t *testing.T) {
		decrypt, err := HexDecode([]byte("48656c6c6f20576f726c64"))
		assert.Equal(t, nil, err)
		assert.Equal(t, "Hello World", string(decrypt))
	})
}
