package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA1(t *testing.T) {
	assert.Equal(t, "40bd001563085fc35165329ea1ff5c5ecbdbbeef", SHA1("123"))
}
