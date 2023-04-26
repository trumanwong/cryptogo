package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleHexEncode() {
	encrypt := HexEncode([]byte("Hello World"))
	fmt.Println(string(encrypt))
	// Output: 48656c6c6f20576f726c64
}

func ExampleHexDecode() {
	decrypt, err := HexDecode([]byte("48656c6c6f20576f726c64"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypt))
	// Output: Hello World
}

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
