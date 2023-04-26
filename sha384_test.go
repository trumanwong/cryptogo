package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA384() {
	fmt.Println(SHA384("TrumanWong"))
	// Output: 9bc8b8e00f51df7c8b00bd5f04a71ab397060a4327283e620883572aa0e0e4f6b468384ab35dbe1a1d380b8b1b221bc3
}

func TestSHA384(t *testing.T) {
	assert.Equal(t, "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", SHA384("123"))
}

func ExampleHmacSHA384() {
	fmt.Println(HmacSHA384("", "TrumanWong"))
	// Output: b9da6d3260e34c71b548925261a731458f4dd1dcaf994deec2356538188fa5cc9410a3e51970423660804ad9d4f8574d
}

func TestHmacSHA384(t *testing.T) {
	assert.Equal(t, "818f69e64d65f4dedd1a25007512191e113ae1f4ebb00b8028cf81717f279ff042623fcfa819466d1a146d87561c1fea", HmacSHA384("", "123"))
}
