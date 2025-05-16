package cryptogo

import "testing"

func TestCaesarEncrypt(t *testing.T) {
	tests := []struct {
		plaintext string
		shift     int
		expected  string
	}{
		{"Hello World", 4, "Lipps Asvph"},
		{"TrumanWong", 5, "YwzrfsBtsl"},
	}

	for _, test := range tests {
		result := CaesarEncrypt(test.plaintext, test.shift)
		if result != test.expected {
			t.Errorf("CaesarEncrypt(%s, %d) = %s; expected %s", test.plaintext, test.shift, result, test.expected)
		}
	}
}

func TestCaesarDecrypt(t *testing.T) {
	tests := []struct {
		ciphertext string
		shift      int
		expected   string
	}{
		{"Lipps Asvph", 4, "Hello World"},
		{"YwzrfsBtsl", 5, "TrumanWong"},
	}

	for _, test := range tests {
		result := CaesarDecrypt(test.ciphertext, test.shift)
		if result != test.expected {
			t.Errorf("CaesarDecrypt(%s, %d) = %s; expected %s", test.ciphertext, test.shift, result, test.expected)
		}
	}
}
