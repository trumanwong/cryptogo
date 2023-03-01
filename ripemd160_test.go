package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRIPEMD160(t *testing.T) {
	assert.Equal(t, "e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", RIPEMD160("123"))
}
