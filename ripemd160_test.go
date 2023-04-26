package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleRIPEMD160() {
	fmt.Println(RIPEMD160("TrumanWong"))
	// Output: 577d5d4c78049fcfeeeb4674bc4bd5c8e55ef3bf
}

func TestRIPEMD160(t *testing.T) {
	assert.Equal(t, "e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", RIPEMD160("123"))
}

func ExampleHmacRIPEMD160() {
	fmt.Println(HmacRIPEMD160("", "TrumanWong"))
	// Output: a4c9440f8cce286e42b959468a048c2dd7bfa8b0
}

func TestHmacRIPEMD160(t *testing.T) {
	assert.Equal(t, "53bac0e52d581d4c15dd6771e040871566430752", HmacRIPEMD160("", "123"))
}
