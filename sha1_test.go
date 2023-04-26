package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA1() {
	fmt.Println(SHA1("TrumanWong"))
	// Output: b26f1810bfa1cf2df0d7b76f7325d35a9b5540e8
}

func TestSHA1(t *testing.T) {
	assert.Equal(t, "40bd001563085fc35165329ea1ff5c5ecbdbbeef", SHA1("123"))
}

func ExampleHmacSHA1() {
	fmt.Println(HmacSHA1("", "TrumanWong"))
	// Output: 95a8c2db5b6ec69c234414411abc429cde8ab081
}

func TestHmacSHA1(t *testing.T) {
	assert.Equal(t, "658a0901623568ea5c3631cf6193a023d657ae4f", HmacSHA1("", "123"))
}
