package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA1(t *testing.T) {
	assert.Equal(t, "40bd001563085fc35165329ea1ff5c5ecbdbbeef", SHA1("123"))
}

func TestHmacSHA1(t *testing.T) {
	assert.Equal(t, "658a0901623568ea5c3631cf6193a023d657ae4f", HmacSHA1("", "123"))
}
