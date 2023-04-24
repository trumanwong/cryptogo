package cryptogo

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"testing"
)

func TestDesCBCEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// DES-CBC Zero padding
		{clearText, key, iv, paddings.Zero, "DQ3gRwc3eKO/ffcphCq45g=="},
		// DES-256-CBC ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "DQ3gRwc3eKPyyFD7howQ1g=="},
		// DES-CBC ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "DQ3gRwc3eKNqV849PnO46w=="},
		// DES-CBC PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "DQ3gRwc3eKPYrkgSi4OJ7A=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := DesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestDesCBCDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// DES-CBC Zero padding
		{"DQ3gRwc3eKO/ffcphCq45g==", key, iv, paddings.Zero, clearText},
		// DES-CBC ANSI X.923 padding
		{"DQ3gRwc3eKPyyFD7howQ1g==", key, iv, paddings.AnsiX923, clearText},
		// DES-CBC ISO/IEC 9797-1 padding
		{"DQ3gRwc3eKNqV849PnO46w==", key, iv, paddings.ISO97971, clearText},
		// DES-CBC PKCS7 padding
		{"DQ3gRwc3eKPYrkgSi4OJ7A==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := DesCBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestDesCBCISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// DES-CBC PKCS7 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := DesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := DesCBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestDesCFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// DES-CFB Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+aM4xRnW2SKzw=="},
		// DES-CFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+aM4xRnW2SKyQ=="},
		// DES-CFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+aM45RnW2SKzw=="},
		// DES-CFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+aM4xJhXWKMyQ=="},
		// DES-192-CFB PKCS7 padding
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := DesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestDesCFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// DES-CFB Zero padding
		{"wqJ35Rm72+aM4xRnW2SKzw==", key, iv, paddings.Zero, clearText},
		// DES-CFB ANSI X.923 padding
		{"wqJ35Rm72+aM4xRnW2SKyQ==", key, iv, paddings.AnsiX923, clearText},
		// DES-CFB ISO/IEC 9797-1 padding
		{"wqJ35Rm72+aM45RnW2SKzw==", key, iv, paddings.ISO97971, clearText},
		// DES-CFB PKCS7 padding
		{"wqJ35Rm72+aM4xJhXWKMyQ==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := DesCFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestDesCFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// DES-CFB PKCS7 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := DesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := DesCFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestDesCTREncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// DES-CTR Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+Yvde8W2Xn2CA=="},
		// DES-CTR ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+Yvde8W2Xn2Dg=="},
		// DES-CTR ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+YvdW8W2Xn2CA=="},
		// DES-CTR PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+YvdekQ33/wDg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := DesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestDesCTRDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// DES-CTR Zero padding
		{"wqJ35Rm72+Yvde8W2Xn2CA==", key, iv, paddings.Zero, clearText},
		// DES-CTR ANSI X.923 padding
		{"wqJ35Rm72+Yvde8W2Xn2Dg==", key, iv, paddings.AnsiX923, clearText},
		// DES-CTR ISO/IEC 9797-1 padding
		{"wqJ35Rm72+YvdW8W2Xn2CA==", key, iv, paddings.ISO97971, clearText},
		// DES-CTR PKCS7 padding
		{"wqJ35Rm72+YvdekQ33/wDg==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CTR-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := DesCTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestDesCTRISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// DES-CTR PKCS7 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := DesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := DesCTRDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestDesECBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// DES-ECB Zero padding
		{clearText, key, paddings.Zero, "rayjMG0QXSYRXd2HJ0J4rg=="},
		// DES-ECB ANSI X.923 padding
		{clearText, key, paddings.AnsiX923, "rayjMG0QXSY90vhug8VPLw=="},
		{clearText, key, paddings.ISO97971, "rayjMG0QXSYkcqxjmAFU5w=="},
		// DES-ECB PKCS7 padding
		{clearText, key, paddings.PKCS7, "rayjMG0QXSaYbesVWAdnGQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := DesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestDesECBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// DES-ECB Zero padding
		{"rayjMG0QXSYRXd2HJ0J4rg==", key, paddings.Zero, clearText},
		// DES-ECB ANSI X.923 padding
		{"rayjMG0QXSY90vhug8VPLw==", key, paddings.AnsiX923, clearText},
		// DES-ECB ISO/IEC 9797-1 padding
		{"rayjMG0QXSYkcqxjmAFU5w==", key, paddings.ISO97971, clearText},
		// DES-ECB PKCS7 padding
		{"rayjMG0QXSaYbesVWAdnGQ==", key, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := DesECBDecrypt(src, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestDesECBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
	}{
		// DES-ECB PKCS7 padding
		{clearText, key, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := DesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := DesECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestDesOFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// DES-OFB Zero padding
		{clearText, key, iv, paddings.Zero, "wqJ35Rm72+aHEpjfKW8Sqg=="},
		// DES-OFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "wqJ35Rm72+aHEpjfKW8SrA=="},
		// DES-OFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "wqJ35Rm72+aHEhjfKW8Sqg=="},
		// DES-OFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "wqJ35Rm72+aHEp7ZL2kUrA=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := DesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestDesOFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// DES-OFB Zero padding
		{"wqJ35Rm72+aHEpjfKW8Sqg==", key, iv, paddings.Zero, clearText},
		// DES-OFB ANSI X.923 padding
		{"wqJ35Rm72+aHEpjfKW8SrA==", key, iv, paddings.AnsiX923, clearText},
		// DES-OFB ISO/IEC 9797-1 padding
		{"wqJ35Rm72+aHEhjfKW8Sqg==", key, iv, paddings.ISO97971, clearText},
		// DES-OFB PKCS7 padding
		{"wqJ35Rm72+aHEp7ZL2kUrA==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-OFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := DesOFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestDesOFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("12345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// DES-OFB PKCS7 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("DES-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := DesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := DesOFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
