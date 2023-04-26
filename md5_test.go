package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleMD5() {
	fmt.Println(MD5("123"))
	// Output: 202cb962ac59075b964b07152d234b70
}

func TestMD5(t *testing.T) {
	assert.Equal(t, "202cb962ac59075b964b07152d234b70", MD5("123"))
}
func ExampleMD5ToLower() {
	fmt.Println(MD5ToLower("123"))
	// Output: 202cb962ac59075b964b07152d234b70
}

func TestMD5ToLower(t *testing.T) {
	assert.Equal(t, "202cb962ac59075b964b07152d234b70", MD5ToLower("123"))
}

func ExampleMD5ToUpper() {
	fmt.Println(MD5ToUpper("123"))
	// Output: 202CB962AC59075B964B07152D234B70
}

func TestMD5ToUpper(t *testing.T) {
	assert.Equal(t, "202CB962AC59075B964B07152D234B70", MD5ToUpper("123"))
}

func ExampleMD5Sixteen() {
	fmt.Println(MD5Sixteen("123"))
	// Output: ac59075b964b0715
}

func TestMD5Sixteen(t *testing.T) {
	assert.Equal(t, "ac59075b964b0715", MD5Sixteen("123"))
}

func ExampleMD5SixteenToUpper() {
	fmt.Println(MD5SixteenToUpper("123"))
	// Output: AC59075B964B0715
}

func TestMD5SixteenToUpper(t *testing.T) {
	assert.Equal(t, "AC59075B964B0715", MD5SixteenToUpper("123"))
}

func ExampleMD5SixteenToLower() {
	fmt.Println(MD5SixteenToLower("123"))
	// Output: ac59075b964b0715
}

func TestMD5SixteenToLower(t *testing.T) {
	assert.Equal(t, "ac59075b964b0715", MD5SixteenToLower("123"))
}

func ExampleHmacMD5() {
	fmt.Println(HmacMD5("TrumanWong", "123"))
	// Output: 1a152759b05a1cc0e2841a7fb58a559b
}

func TestHmacMD5(t *testing.T) {
	assert.Equal(t, "c8ec4ed8338e4d0a81e75ba3b9d290a8", HmacMD5("", "123"))
}
