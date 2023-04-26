package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA224() {
	fmt.Println(SHA224("TrumanWong"))
	// Output: d1de0e837d09504b7389e5bd5a8336955cc795f1ec134cea5124ef0c
}

func TestSHA224(t *testing.T) {
	assert.Equal(t, "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f", SHA224("123"))
}

func ExampleHmacSHA224() {
	fmt.Println(HmacSHA224("", "TrumanWong"))
	// Output: 9f7603cf61594456d90d89984676d56baac1eb8b09e2941f49709885
}

func TestHmacSHA224(t *testing.T) {
	assert.Equal(t, "21062e31322f0e062752b22b92742d92e069256dfee0eb9b58fb4044", HmacSHA224("", "123"))
}
