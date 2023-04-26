package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA512() {
	fmt.Println(SHA512("TrumanWong"))
	// Output: e450d416e9d4bd2a3260d6c0a96156946bcc6fe37cf1a60c7e535281babaa598b9bae5a81d170da2ea9acc0f69feb39c958c0e7304a459c9c57d58294e9ad63e
}

func TestSHA512(t *testing.T) {
	assert.Equal(t, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2", SHA512("123"))
}

func ExampleHmacSHA512() {
	fmt.Println(HmacSHA512("", "TrumanWong"))
	// Output: 8cd5a8cbdc537604c1ac0e72d7cee562f38c166b471e85e76fe6c2632e0e18c1f6720eaad0134541d23da8aa2356b82cc86aedc868fc119760dd97781795481d
}

func TestHmacSHA512(t *testing.T) {
	assert.Equal(t, "a90cf1763b872e1e50ecfdf71f0834604e654ba977f7522b021d05e9d6add2343ef769a7554b7c959875120029373415161e46bd99504630ae30ba108fbcee37", HmacSHA512("", "123"))
}
