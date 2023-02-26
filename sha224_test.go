package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA224(t *testing.T) {
	assert.Equal(t, "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f", SHA224("123"))
}
