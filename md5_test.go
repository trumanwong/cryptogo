package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMD5(t *testing.T) {
	assert.Equal(t, "202cb962ac59075b964b07152d234b70", MD5("123"))
}

func TestMD5ToLower(t *testing.T) {
	assert.Equal(t, "202cb962ac59075b964b07152d234b70", MD5ToLower("123"))
}

func TestMD5ToUpper(t *testing.T) {
	assert.Equal(t, "202CB962AC59075B964B07152D234B70", MD5ToUpper("123"))
}

func TestMD5Sixteen(t *testing.T) {
	assert.Equal(t, "ac59075b964b0715", MD5Sixteen("123"))
}

func TestMD5SixteenToUpper(t *testing.T) {
	assert.Equal(t, "AC59075B964B0715", MD5SixteenToUpper("123"))
}

func TestMD5SixteenToLower(t *testing.T) {
	assert.Equal(t, "ac59075b964b0715", MD5SixteenToLower("123"))
}
