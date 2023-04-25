package cryptogo

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"testing"
)

func TestTripleDesCBCEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-Des-CBC Zero padding
		{clearText, key, iv, paddings.Zero, "DQ3gRwc3eKO/ffcphCq45g=="},
		// Triple-Des-CBC ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "DQ3gRwc3eKPyyFD7howQ1g=="},
		// Triple-Des-CBC ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "DQ3gRwc3eKNqV849PnO46w=="},
		// Triple-Des-CBC PKCS5padding
		{clearText, key, iv, paddings.PKCS5, "DQ3gRwc3eKPYrkgSi4OJ7A=="},
		// Triple-Des-CBC PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "DQ3gRwc3eKPYrkgSi4OJ7A=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTripleDesCBCDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-Des-CBC Zero padding
		{"DQ3gRwc3eKO/ffcphCq45g==", key, iv, paddings.Zero, clearText},
		// Triple-Des-CBC ANSI X.923 padding
		{"DQ3gRwc3eKPyyFD7howQ1g==", key, iv, paddings.AnsiX923, clearText},
		// Triple-Des-CBC ISO/IEC 9797-1 padding
		{"DQ3gRwc3eKNqV849PnO46w==", key, iv, paddings.ISO97971, clearText},
		// Triple-Des-CBC PKCS7 padding
		{"DQ3gRwc3eKPYrkgSi4OJ7A==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TripleDesCBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTripleDesCBCISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-Des-CBC ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TripleDesCBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTripleDesCFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-Des-CFB Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+aM4xRnW2SKzw=="},
		// Triple-Des-CFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+aM4xRnW2SKyQ=="},
		// Triple-Des-CFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+aM45RnW2SKzw=="},
		// Triple-Des-CFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+aM4xJhXWKMyQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTripleDesCFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-Des-CFB Zero padding
		{"wqJ35Rm72+aM4xRnW2SKzw==", key, iv, paddings.Zero, clearText},
		// Triple-Des-CFB ANSI X.923 padding
		{"wqJ35Rm72+aM4xRnW2SKyQ==", key, iv, paddings.AnsiX923, clearText},
		// Triple-Des-CFB ISO/IEC 9797-1 padding
		{"wqJ35Rm72+aM45RnW2SKzw==", key, iv, paddings.ISO97971, clearText},
		// Triple-Des-CFB PKCS7 padding
		{"wqJ35Rm72+aM4xJhXWKMyQ==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TripleDesCFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTripleDesCFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-Des-CFB ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TripleDesCFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTripleDesCTREncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-Des-CTR Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+Yvde8W2Xn2CA=="},
		// Triple-Des-CTR ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+Yvde8W2Xn2Dg=="},
		// Triple-Des-CTR ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+YvdW8W2Xn2CA=="},
		// Triple-Des-CTR PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+YvdekQ33/wDg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTripleDesCTRDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-Des-CTR Zero padding
		{"wqJ35Rm72+Yvde8W2Xn2CA==", key, iv, paddings.Zero, clearText},
		// Triple-Des-CTR ANSI X.923 padding
		{"wqJ35Rm72+Yvde8W2Xn2Dg==", key, iv, paddings.AnsiX923, clearText},
		// Triple-Des-CTR ISO/IEC 9797-1 padding
		{"wqJ35Rm72+YvdW8W2Xn2CA==", key, iv, paddings.ISO97971, clearText},
		// Triple-Des-CTR PKCS7 padding
		{"wqJ35Rm72+YvdekQ33/wDg==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CTR-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TripleDesCTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTripleDesCTRISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-Des-CTR ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TripleDesCTRDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTripleDesECBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-Des-ECB Zero padding
		{clearText, key, paddings.Zero, "rayjMG0QXSYRXd2HJ0J4rg=="},
		// Triple-Des-ECB ANSI X.923 padding
		{clearText, key, paddings.AnsiX923, "rayjMG0QXSY90vhug8VPLw=="},
		// Triple-Des-ECB ISO/IEC 9797-1 padding
		{clearText, key, paddings.ISO97971, "rayjMG0QXSYkcqxjmAFU5w=="},
		// Triple-Des-ECB PKCS7 padding
		{clearText, key, paddings.PKCS7, "rayjMG0QXSaYbesVWAdnGQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTripleDesECBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-Des-ECB Zero padding
		{"rayjMG0QXSYRXd2HJ0J4rg==", key, paddings.Zero, clearText},
		// Triple-Des-ECB ANSI X.923 padding
		{"rayjMG0QXSY90vhug8VPLw==", key, paddings.AnsiX923, clearText},
		// Triple-Des-ECB ISO/IEC 9797-1 padding
		{"rayjMG0QXSYkcqxjmAFU5w==", key, paddings.ISO97971, clearText},
		// Triple-Des-ECB PKCS7 padding
		{"rayjMG0QXSaYbesVWAdnGQ==", key, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TripleDesECBDecrypt(src, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTripleDesECBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-Des-ECB ISO 10126 padding
		{clearText, key, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := TripleDesECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTripleDesOFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-Des-OFB Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+aHEpjfKW8Sqg=="},
		// Triple-Des-OFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+aHEpjfKW8SrA=="},
		// Triple-Des-OFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+aHEhjfKW8Sqg=="},
		// Triple-Des-OFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+aHEp7ZL2kUrA=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTripleDesOFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-Des-OFB Zero padding
		{"wqJ35Rm72+aHEpjfKW8Sqg==", key, iv, paddings.Zero, clearText},
		// Triple-Des-OFB ANSI X.923 padding
		{"wqJ35Rm72+aHEpjfKW8SrA==", key, iv, paddings.AnsiX923, clearText},
		// Triple-Des-OFB ISO/IEC 9797-1 padding
		{"wqJ35Rm72+aHEhjfKW8Sqg==", key, iv, paddings.ISO97971, clearText},
		// Triple-Des-OFB PKCS7 padding
		{"wqJ35Rm72+aHEp7ZL2kUrA==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-OFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TripleDesOFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTripleDesOFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-Des-OFB ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Triple-Des-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := TripleDesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TripleDesOFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
