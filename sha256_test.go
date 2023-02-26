package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA256(t *testing.T) {
	assert.Equal(t, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", SHA256("123"))
}
