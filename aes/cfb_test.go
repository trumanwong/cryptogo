package aes

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesCFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      cipherPadding
		Expected  string
	}{
		// AES-128-CFB Zero padding
		{clearText, aes128Key, iv, Zero, "Od5pO4YprY9UqIxokeQo4A=="},
		// AES-192-CFB Zero padding
		{clearText, aes192Key, iv, Zero, "kcakAFrfOQPVlzu035jYLw=="},
		// AES-256-CFB Zero padding
		{clearText, aes256Key, iv, Zero, "fcy7eDqucP7lG9av6MVgvQ=="},
		// AES-128-CFB ANSI X.923 padding
		{clearText, aes128Key, iv, AnsiX923, "Od5pO4YprY9UqIxokeQo5g=="},
		// AES-192-CFB ANSI X.923 padding
		{clearText, aes192Key, iv, AnsiX923, "kcakAFrfOQPVlzu035jYKQ=="},
		// AES-256-CFB ANSI X.923 padding
		{clearText, aes256Key, iv, AnsiX923, "fcy7eDqucP7lG9av6MVguw=="},
		// AES-128-CFB ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, ISO97971, "Od5pO4YprY9UqAxokeQo4A=="},
		// AES-192-CFB ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, ISO97971, "kcakAFrfOQPVl7u035jYLw=="},
		// AES-256-CFB ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, ISO97971, "fcy7eDqucP7lG1av6MVgvQ=="},
		// AES-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, PKCS7, "Od5pO4YprY9UqIpul+Iu5g=="},
		// AES-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, PKCS7, "kcakAFrfOQPVlz2y2Z7eKQ=="},
		// AES-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, PKCS7, "fcy7eDqucP7lG9Cp7sNmuw=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := CFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestAesCFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     cipherPadding
		Expected string
	}{
		// AES-128-CFB Zero padding
		{"Od5pO4YprY9UqIxokeQo4A==", aes128Key, iv, Zero, clearText},
		// AES-192-CFB Zero padding
		{"kcakAFrfOQPVlzu035jYLw==", aes192Key, iv, Zero, clearText},
		// AES-256-CFB Zero padding
		{"fcy7eDqucP7lG9av6MVgvQ==", aes256Key, iv, Zero, clearText},
		// AES-128-CFB ANSI X.923 padding
		{"Od5pO4YprY9UqIxokeQo5g==", aes128Key, iv, AnsiX923, clearText},
		// AES-192-CFB ANSI X.923 padding
		{"kcakAFrfOQPVlzu035jYKQ==", aes192Key, iv, AnsiX923, clearText},
		// AES-256-CFB ANSI X.923 padding
		{"fcy7eDqucP7lG9av6MVguw==", aes256Key, iv, AnsiX923, clearText},
		// AES-128-CFB ISO/IEC 9797-1 padding
		{"Od5pO4YprY9UqAxokeQo4A==", aes128Key, iv, ISO97971, clearText},
		// AES-192-CFB ISO/IEC 9797-1 padding
		{"kcakAFrfOQPVl7u035jYLw==", aes192Key, iv, ISO97971, clearText},
		// AES-256-CFB ISO/IEC 9797-1 padding
		{"fcy7eDqucP7lG1av6MVgvQ==", aes256Key, iv, ISO97971, clearText},
		// AES-128-CFB PKCS7 padding
		{"Od5pO4YprY9UqIpul+Iu5g==", aes128Key, iv, PKCS7, clearText},
		// AES-192-CFB PKCS7 padding
		{"kcakAFrfOQPVlz2y2Z7eKQ==", aes192Key, iv, PKCS7, clearText},
		// AES-256-CFB PKCS7 padding
		{"fcy7eDqucP7lG9Cp7sNmuw==", aes256Key, iv, PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := CFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestAesCFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      cipherPadding
	}{
		// AES-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, ISO10126},
		// AES-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, ISO10126},
		// AES-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := CFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := CFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
