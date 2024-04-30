package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSm3() {
	fmt.Println(Sm3([]byte("TrumanWong")))
	// Output: ad878f7dac4141200b516abd9fc2d1bf238e6d6df9a98b9c959569515ef5c6b9
}

func TestSm3(t *testing.T) {
	assert.Equal(t, "ad878f7dac4141200b516abd9fc2d1bf238e6d6df9a98b9c959569515ef5c6b9", Sm3([]byte("TrumanWong")))
}
