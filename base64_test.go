package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleBase64Encode() {
	encode := Base64Encode([]byte("TrumanWong"))
	fmt.Println(string(encode))
	// Output: VHJ1bWFuV29uZw==
}

func TestBase64Encode(t *testing.T) {
	t.Run("TestBase64Encode", func(t *testing.T) {
		assert.Equal(t, []byte("VHJ1bWFuV29uZw=="), Base64Encode([]byte("TrumanWong")))
	})
}

func ExampleBase64Decode() {
	decode, err := Base64Decode([]byte("VHJ1bWFuV29uZw=="))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decode))
	// Output: TrumanWong
}

func TestBase64Decode(t *testing.T) {
	t.Run("TestBase64Decode", func(t *testing.T) {
		ret, err := Base64Decode([]byte("VHJ1bWFuV29uZw=="))
		assert.NoError(t, err)
		assert.Equal(t, []byte("TrumanWong"), ret)
	})
}
