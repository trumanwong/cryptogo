package aes

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesCBCEncrypt(t *testing.T) {
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
		// AES-128-CBC Zero padding
		{clearText, aes128Key, iv, Zero, "Acdkp3UqE2Gp7BDkzhQIuQ=="},
		// AES-192-CBC Zero padding
		{clearText, aes192Key, iv, Zero, "WuY2vCpyq2dFxtTGxG7/Dw=="},
		// AES-256-CBC Zero padding
		{clearText, aes256Key, iv, Zero, "8EvaLE71d/3FyeVzcnIeuQ=="},
		// AES-128-CBC ANSI X.923 padding
		{clearText, aes128Key, iv, AnsiX923, "4AT4Wvgafn4Q3bXVGo7J7g=="},
		// AES-192-CBC ANSI X.923 padding
		{clearText, aes192Key, iv, AnsiX923, "4gLpA4mcExU/qp2sg5es4w=="},
		// AES-256-CBC ANSI X.923 padding
		{clearText, aes256Key, iv, AnsiX923, "IJ2D7riwgJhBmdMlDhrmXw=="},
		// AES-128-CBC ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, ISO97971, "WJEdM6m2M+ZBkd8GC7L3wA=="},
		// AES-192-CBC ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, ISO97971, "0TeGamqtZ4sZ/Wtr14w1IA=="},
		// AES-256-CBC ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, ISO97971, "wqfgGDLgBIBa6lV+OVTC3Q=="},
		// AES-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, PKCS7, "/qVy6gciLZGACXhW4HjzCQ=="},
		// AES-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, PKCS7, "KYxEGNuVwJjLuFUQpLS93w=="},
		// AES-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, PKCS7, "7ZA4COnkF1jW7tnRzQq3VQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := CBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestAesCBCDecrypt(t *testing.T) {
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
		// AES-128-CBC Zero padding
		{"Acdkp3UqE2Gp7BDkzhQIuQ==", aes128Key, iv, Zero, clearText},
		// AES-192-CBC Zero padding
		{"WuY2vCpyq2dFxtTGxG7/Dw==", aes192Key, iv, Zero, clearText},
		// AES-256-CBC Zero padding
		{"8EvaLE71d/3FyeVzcnIeuQ==", aes256Key, iv, Zero, clearText},
		// AES-128-CBC ANSI X.923 padding
		{"4AT4Wvgafn4Q3bXVGo7J7g==", aes128Key, iv, AnsiX923, clearText},
		// AES-192-CBC ANSI X.923 padding
		{"4gLpA4mcExU/qp2sg5es4w==", aes192Key, iv, AnsiX923, clearText},
		// AES-256-CBC ANSI X.923 padding
		{"IJ2D7riwgJhBmdMlDhrmXw==", aes256Key, iv, AnsiX923, clearText},
		// AES-128-CBC ISO/IEC 9797-1 padding
		{"WJEdM6m2M+ZBkd8GC7L3wA==", aes128Key, iv, ISO97971, clearText},
		// AES-192-CBC ISO/IEC 9797-1 padding
		{"0TeGamqtZ4sZ/Wtr14w1IA==", aes192Key, iv, ISO97971, clearText},
		// AES-256-CBC ISO/IEC 9797-1 padding
		{"wqfgGDLgBIBa6lV+OVTC3Q==", aes256Key, iv, ISO97971, clearText},
		// AES-128-CBC PKCS7 padding
		{"/qVy6gciLZGACXhW4HjzCQ==", aes128Key, iv, PKCS7, clearText},
		// AES-192-CBC PKCS7 padding
		{"KYxEGNuVwJjLuFUQpLS93w==", aes192Key, iv, PKCS7, clearText},
		// AES-256-CBC PKCS7 padding
		{"7ZA4COnkF1jW7tnRzQq3VQ==", aes256Key, iv, PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := CBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestAesCBCISO10126(t *testing.T) {
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
		// AES-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, ISO10126},
		// AES-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, ISO10126},
		// AES-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := CBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := CBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
