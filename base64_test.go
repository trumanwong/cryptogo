package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	t.Run("TestBase64Encode", func(t *testing.T) {
		assert.Equal(t, []byte("VHJ1bWFuV29uZw=="), Base64Encode([]byte("TrumanWong")))
	})
}

func TestBase64Decode(t *testing.T) {
	t.Run("TestBase64Decode", func(t *testing.T) {
		assert.Equal(t, []byte("TrumanWong"), Base64Encode([]byte("VHJ1bWFuV29uZw==")))
	})
}
