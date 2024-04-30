package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleBase32Encode() {
	encode := Base32Encode([]byte("TrumanWong"))
	fmt.Println(string(encode))
	// Output: KRZHK3LBNZLW63TH
}

func TestBase32Encode(t *testing.T) {
	t.Run("TestBase32Encode", func(t *testing.T) {
		assert.Equal(t, []byte("KRZHK3LBNZLW63TH"), Base32Encode([]byte("TrumanWong")))
	})
}

func ExampleBase32Decode() {
	decode, err := Base32Decode([]byte("KRZHK3LBNZLW63TH"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decode))
	// Output: TrumanWong
}

func TestBase32Decode(t *testing.T) {
	t.Run("TestBase32Decode", func(t *testing.T) {
		ret, err := Base32Decode([]byte("KRZHK3LBNZLW63TH"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("TrumanWong"), ret)
	})
}
