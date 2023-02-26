package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA384(t *testing.T) {
	assert.Equal(t, "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", SHA384("123"))
}
