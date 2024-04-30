package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleMorseEncode() {
	encode, err := MorseEncode([]byte("TrumanWong"), "|")
	if err != nil {
		return
	}
	fmt.Println(encode)
	// Output: -|.-.|..-|--|.-|-.|.--|---|-.|--.
}

func TestMorseEncode(t *testing.T) {
	tests := []struct {
		input     string
		separator string
		expected  string
	}{
		{"", "", ""},
		{"1", "/", ".----"},
		{"a", "/", ".-"},
		{"TrumanWong", "|", "-|.-.|..-|--|.-|-.|.--|---|-.|--."},
	}

	for _, v := range tests {
		t.Run("MorseEncode", func(t *testing.T) {
			dst, err := MorseEncode([]byte(v.input), v.separator)

			assert.NoError(t, err)
			assert.Equal(t, v.expected, dst)
		})

	}
}

func ExampleMorseDecode() {
	decode, err := MorseDecode([]byte("-|.-.|..-|--|.-|-.|.--|---|-.|--."), "|")
	if err != nil {
		return
	}
	fmt.Println(decode)
	// Output: trumanwong
}

func TestMorseDecode(t *testing.T) {
	tests := []struct {
		input     string
		separator string
		expected  string
	}{
		{"", "", ""},
		{".----", "/", "1"},
		{".-", "/", "a"},
		{"-|.-.|..-|--|.-|-.|.--|---|-.|--.", "|", "TrumanWong"},
	}

	for _, v := range tests {
		t.Run("MorseDecode", func(t *testing.T) {
			dst, err := MorseDecode([]byte(v.input), v.separator)

			assert.NoError(t, err)
			assert.Equal(t, v.expected, dst)
		})

	}
}
