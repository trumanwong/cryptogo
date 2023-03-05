package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA384(t *testing.T) {
	assert.Equal(t, "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", SHA384("123"))
}

func TestHmacSHA384(t *testing.T) {
	assert.Equal(t, "818f69e64d65f4dedd1a25007512191e113ae1f4ebb00b8028cf81717f279ff042623fcfa819466d1a146d87561c1fea", HmacSHA384("", "123"))
}
