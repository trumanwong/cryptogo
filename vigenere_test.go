package cryptogo

import "testing"

func TestVigenereEncrypt(t *testing.T) {
	tests := []struct {
		plaintext string
		key       string
		expected  string
	}{
		{"Hello World", "TrumanWong", "Avfxo Jkfyj"},
		{"Attack at Dawn!", "TrumanWong", "Tknmcx wh Qgpe!"},
	}

	for _, test := range tests {
		result := VigenereEncrypt(test.plaintext, test.key)
		if result != test.expected {
			t.Errorf("VigenereEncrypt(%s, %s) = %s; expected %s", test.plaintext, test.key, result, test.expected)
		}
	}
}

func TestVigenereDecrypt(t *testing.T) {
	tests := []struct {
		ciphertext string
		key        string
		expected   string
	}{
		{"Avfxo Jkfyj", "TrumanWong", "Hello World"},
		{"Tknmcx wh Qgpe!", "TrumanWong", "Attack at Dawn!"},
	}
	for _, test := range tests {
		result := VigenereDecrypt(test.ciphertext, test.key)
		if result != test.expected {
			t.Errorf("VigenereDecrypt(%s, %s) = %s; expected %s", test.ciphertext, test.key, result, test.expected)
		}
	}
}
