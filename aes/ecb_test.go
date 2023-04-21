package aes

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesECBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      cipherPadding
		Expected  string
	}{
		// AES-128-ECB Zero padding
		{clearText, aes128Key, Zero, "G4q6Xt8NyBS9Gi2rfgdleA=="},
		// AES-192-ECB Zero padding
		{clearText, aes192Key, Zero, "JW3kOm2/oF2zB4uaZl41EQ=="},
		// AES-256-ECB Zero padding
		{clearText, aes256Key, Zero, "fGPDkFvsv58UHYxXlbeSQA=="},
		// AES-128-ECB ANSI X.923 padding
		{clearText, aes128Key, AnsiX923, "iUycGCq9LDb33ZZ5eBKmZg=="},
		// AES-192-ECB ANSI X.923 padding
		{clearText, aes192Key, AnsiX923, "wpFjQRmpDfLd0erw0s6+Zw=="},
		// AES-256-ECB ANSI X.923 padding
		{clearText, aes256Key, AnsiX923, "ZrtYnoD3zs2MFcTrdke0jg=="},
		// AES-128-ECB ISO/IEC 9797-1 padding
		{clearText, aes128Key, ISO97971, "LFq+YhVcR3NLWeX1SoUv+w=="},
		// AES-192-ECB ISO/IEC 9797-1 padding
		{clearText, aes192Key, ISO97971, "vrMSznj0zvojBprXuMXLUA=="},
		// AES-256-ECB ISO/IEC 9797-1 padding
		{clearText, aes256Key, ISO97971, "OTg2a5gyTaBOsr1wpI+I4A=="},
		// AES-128-ECB PKCS7 padding
		{clearText, aes128Key, PKCS7, "ErYDQkJwHpgIKp+FMKZ0yQ=="},
		// AES-192-ECB PKCS7 padding
		{clearText, aes192Key, PKCS7, "H/wisoDcYpEkgzExMLcofA=="},
		// AES-256-ECB PKCS7 padding
		{clearText, aes256Key, PKCS7, "nLyxDaKfWPdt+mXnZSWj5w=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := ECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestAesECBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Mode     cipherPadding
		Expected string
	}{
		// AES-128-ECB Zero padding
		{"G4q6Xt8NyBS9Gi2rfgdleA==", aes128Key, Zero, clearText},
		// AES-192-ECB Zero padding
		{"JW3kOm2/oF2zB4uaZl41EQ==", aes192Key, Zero, clearText},
		// AES-256-ECB Zero padding
		{"fGPDkFvsv58UHYxXlbeSQA==", aes256Key, Zero, clearText},
		// AES-128-ECB ANSI X.923 padding
		{"iUycGCq9LDb33ZZ5eBKmZg==", aes128Key, AnsiX923, clearText},
		// AES-192-ECB ANSI X.923 padding
		{"wpFjQRmpDfLd0erw0s6+Zw==", aes192Key, AnsiX923, clearText},
		// AES-256-ECB ANSI X.923 padding
		{"ZrtYnoD3zs2MFcTrdke0jg==", aes256Key, AnsiX923, clearText},
		// AES-128-ECB ISO/IEC 9797-1 padding
		{"LFq+YhVcR3NLWeX1SoUv+w==", aes128Key, ISO97971, clearText},
		// AES-192-ECB ISO/IEC 9797-1 padding
		{"vrMSznj0zvojBprXuMXLUA==", aes192Key, ISO97971, clearText},
		// AES-256-ECB ISO/IEC 9797-1 padding
		{"OTg2a5gyTaBOsr1wpI+I4A==", aes256Key, ISO97971, clearText},
		// AES-128-ECB PKCS7 padding
		{"ErYDQkJwHpgIKp+FMKZ0yQ==", aes128Key, PKCS7, clearText},
		// AES-192-ECB PKCS7 padding
		{"H/wisoDcYpEkgzExMLcofA==", aes192Key, PKCS7, clearText},
		// AES-256-ECB PKCS7 padding
		{"nLyxDaKfWPdt+mXnZSWj5w==", aes256Key, PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := ECBDecrypt(src, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestAesECBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      cipherPadding
	}{
		// AES-128-ECB PKCS7 padding
		{clearText, aes128Key, ISO10126},
		// AES-192-ECB PKCS7 padding
		{clearText, aes192Key, ISO10126},
		// AES-256-ECB PKCS7 padding
		{clearText, aes256Key, ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := ECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := ECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
