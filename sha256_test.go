package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA256() {
	fmt.Println(SHA256("TrumanWong"))
	// Output: 0563f622897657ea42da10bd2c64a08573f7213c99e645623cacf9edc04b238f
}

func TestSHA256(t *testing.T) {
	assert.Equal(t, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", SHA256("123"))
}

func ExampleHmacSHA256() {
	fmt.Println(HmacSHA256("", "TrumanWong"))
	// Output: e8d589fc8a14f7f24a7b2a50412dad4f7f9d662e6cb6690ef2e68377f7494f9f
}

func TestHmacSHA256(t *testing.T) {
	assert.Equal(t, "c0cc0dfdfaef2370e4d56711175fe349def6ed4cba25d3c7a01fc6ef6568220d", HmacSHA256("", "123"))
}
