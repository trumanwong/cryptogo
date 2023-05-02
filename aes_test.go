package cryptogo

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"io"
	"testing"
)

func ExampleAesCBCEncrypt() {
	encrypt, err := AesCBCEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS5)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: Acdkp3UqE2Gp7BDkzhQIuQ==
}

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
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// AES-128-CBC Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "Acdkp3UqE2Gp7BDkzhQIuQ=="},
		// AES-192-CBC Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "WuY2vCpyq2dFxtTGxG7/Dw=="},
		// AES-256-CBC Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "8EvaLE71d/3FyeVzcnIeuQ=="},
		// AES-128-CBC ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "4AT4Wvgafn4Q3bXVGo7J7g=="},
		// AES-192-CBC ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "4gLpA4mcExU/qp2sg5es4w=="},
		// AES-256-CBC ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "IJ2D7riwgJhBmdMlDhrmXw=="},
		// AES-128-CBC ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "WJEdM6m2M+ZBkd8GC7L3wA=="},
		// AES-192-CBC ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "0TeGamqtZ4sZ/Wtr14w1IA=="},
		// AES-256-CBC ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "wqfgGDLgBIBa6lV+OVTC3Q=="},
		// AES-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "/qVy6gciLZGACXhW4HjzCQ=="},
		// AES-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "KYxEGNuVwJjLuFUQpLS93w=="},
		// AES-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "7ZA4COnkF1jW7tnRzQq3VQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := AesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleAesCBCDecrypt() {
	src, err := base64.StdEncoding.DecodeString("Acdkp3UqE2Gp7BDkzhQIuQ==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := AesCBCDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
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
		Mode     paddings.CipherPadding
		Expected string
	}{
		// AES-128-CBC Zero padding
		{"Acdkp3UqE2Gp7BDkzhQIuQ==", aes128Key, iv, paddings.Zero, clearText},
		// AES-192-CBC Zero padding
		{"WuY2vCpyq2dFxtTGxG7/Dw==", aes192Key, iv, paddings.Zero, clearText},
		// AES-256-CBC Zero padding
		{"8EvaLE71d/3FyeVzcnIeuQ==", aes256Key, iv, paddings.Zero, clearText},
		// AES-128-CBC ANSI X.923 padding
		{"4AT4Wvgafn4Q3bXVGo7J7g==", aes128Key, iv, paddings.AnsiX923, clearText},
		// AES-192-CBC ANSI X.923 padding
		{"4gLpA4mcExU/qp2sg5es4w==", aes192Key, iv, paddings.AnsiX923, clearText},
		// AES-256-CBC ANSI X.923 padding
		{"IJ2D7riwgJhBmdMlDhrmXw==", aes256Key, iv, paddings.AnsiX923, clearText},
		// AES-128-CBC ISO/IEC 9797-1 padding
		{"WJEdM6m2M+ZBkd8GC7L3wA==", aes128Key, iv, paddings.ISO97971, clearText},
		// AES-192-CBC ISO/IEC 9797-1 padding
		{"0TeGamqtZ4sZ/Wtr14w1IA==", aes192Key, iv, paddings.ISO97971, clearText},
		// AES-256-CBC ISO/IEC 9797-1 padding
		{"wqfgGDLgBIBa6lV+OVTC3Q==", aes256Key, iv, paddings.ISO97971, clearText},
		// AES-128-CBC PKCS7 padding
		{"/qVy6gciLZGACXhW4HjzCQ==", aes128Key, iv, paddings.PKCS7, clearText},
		// AES-192-CBC PKCS7 padding
		{"KYxEGNuVwJjLuFUQpLS93w==", aes192Key, iv, paddings.PKCS7, clearText},
		// AES-256-CBC PKCS7 padding
		{"7ZA4COnkF1jW7tnRzQq3VQ==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := AesCBCDecrypt(src, v.Key, v.IV, v.Mode)
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
		Mode      paddings.CipherPadding
	}{
		// AES-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// AES-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// AES-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := AesCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := AesCBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleAesCFBEncrypt() {
	encrypt, err := AesCFBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: Od5pO4YprY9UqIxokeQo4A==
}

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
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// AES-128-CFB Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "Od5pO4YprY9UqIxokeQo4A=="},
		// AES-192-CFB Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "kcakAFrfOQPVlzu035jYLw=="},
		// AES-256-CFB Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "fcy7eDqucP7lG9av6MVgvQ=="},
		// AES-128-CFB ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "Od5pO4YprY9UqIxokeQo5g=="},
		// AES-192-CFB ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "kcakAFrfOQPVlzu035jYKQ=="},
		// AES-256-CFB ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "fcy7eDqucP7lG9av6MVguw=="},
		// AES-128-CFB ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "Od5pO4YprY9UqAxokeQo4A=="},
		// AES-192-CFB ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "kcakAFrfOQPVl7u035jYLw=="},
		// AES-256-CFB ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "fcy7eDqucP7lG1av6MVgvQ=="},
		// AES-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "Od5pO4YprY9UqIpul+Iu5g=="},
		// AES-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "kcakAFrfOQPVlz2y2Z7eKQ=="},
		// AES-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "fcy7eDqucP7lG9Cp7sNmuw=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := AesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleAesCFBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("Od5pO4YprY9UqIxokeQo4A==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := AesCFBDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
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
		Mode     paddings.CipherPadding
		Expected string
	}{
		// AES-128-CFB Zero padding
		{"Od5pO4YprY9UqIxokeQo4A==", aes128Key, iv, paddings.Zero, clearText},
		// AES-192-CFB Zero padding
		{"kcakAFrfOQPVlzu035jYLw==", aes192Key, iv, paddings.Zero, clearText},
		// AES-256-CFB Zero padding
		{"fcy7eDqucP7lG9av6MVgvQ==", aes256Key, iv, paddings.Zero, clearText},
		// AES-128-CFB ANSI X.923 padding
		{"Od5pO4YprY9UqIxokeQo5g==", aes128Key, iv, paddings.AnsiX923, clearText},
		// AES-192-CFB ANSI X.923 padding
		{"kcakAFrfOQPVlzu035jYKQ==", aes192Key, iv, paddings.AnsiX923, clearText},
		// AES-256-CFB ANSI X.923 padding
		{"fcy7eDqucP7lG9av6MVguw==", aes256Key, iv, paddings.AnsiX923, clearText},
		// AES-128-CFB ISO/IEC 9797-1 padding
		{"Od5pO4YprY9UqAxokeQo4A==", aes128Key, iv, paddings.ISO97971, clearText},
		// AES-192-CFB ISO/IEC 9797-1 padding
		{"kcakAFrfOQPVl7u035jYLw==", aes192Key, iv, paddings.ISO97971, clearText},
		// AES-256-CFB ISO/IEC 9797-1 padding
		{"fcy7eDqucP7lG1av6MVgvQ==", aes256Key, iv, paddings.ISO97971, clearText},
		// AES-128-CFB PKCS7 padding
		{"Od5pO4YprY9UqIpul+Iu5g==", aes128Key, iv, paddings.PKCS7, clearText},
		// AES-192-CFB PKCS7 padding
		{"kcakAFrfOQPVlz2y2Z7eKQ==", aes192Key, iv, paddings.PKCS7, clearText},
		// AES-256-CFB PKCS7 padding
		{"fcy7eDqucP7lG9Cp7sNmuw==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := AesCFBDecrypt(src, v.Key, v.IV, v.Mode)
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
		Mode      paddings.CipherPadding
	}{
		// AES-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// AES-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// AES-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := AesCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := AesCFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleAesCTREncrypt() {
	encrypt, err := AesCTREncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: Od5pO4YprY9UqIxokeQo4A==
}

func TestAesCTREncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// AES-128-CTR Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "Od5pO4YprY9UqIxokeQo4A=="},
		// AES-192-CTR Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "kcakAFrfOQPVlzu035jYLw=="},
		// AES-256-CTR Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "fcy7eDqucP7lG9av6MVgvQ=="},
		// AES-128-CTR ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "Od5pO4YprY9UqIxokeQo5g=="},
		// AES-192-CTR ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "kcakAFrfOQPVlzu035jYKQ=="},
		// AES-256-CTR ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "fcy7eDqucP7lG9av6MVguw=="},
		// AES-128-CTR ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "Od5pO4YprY9UqAxokeQo4A=="},
		// AES-192-CTR ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "kcakAFrfOQPVl7u035jYLw=="},
		// AES-256-CTR ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "fcy7eDqucP7lG1av6MVgvQ=="},
		// AES-128-CTR PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "Od5pO4YprY9UqIpul+Iu5g=="},
		// AES-192-CTR PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "kcakAFrfOQPVlz2y2Z7eKQ=="},
		// AES-256-CTR PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "fcy7eDqucP7lG9Cp7sNmuw=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := AesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleAesCTRDecrypt() {
	src, err := base64.StdEncoding.DecodeString("Od5pO4YprY9UqIxokeQo4A==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := AesCTRDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func TestAesCTRDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// AES-128-CTR Zero padding
		{"Od5pO4YprY9UqIxokeQo4A==", aes128Key, iv, paddings.Zero, clearText},
		// AES-192-CTR Zero padding
		{"kcakAFrfOQPVlzu035jYLw==", aes192Key, iv, paddings.Zero, clearText},
		// AES-256-CTR Zero padding
		{"fcy7eDqucP7lG9av6MVgvQ==", aes256Key, iv, paddings.Zero, clearText},
		// AES-128-CTR ANSI X.923 padding
		{"Od5pO4YprY9UqIxokeQo5g==", aes128Key, iv, paddings.AnsiX923, clearText},
		// AES-192-CTR ANSI X.923 padding
		{"kcakAFrfOQPVlzu035jYKQ==", aes192Key, iv, paddings.AnsiX923, clearText},
		// AES-256-CTR ANSI X.923 padding
		{"fcy7eDqucP7lG9av6MVguw==", aes256Key, iv, paddings.AnsiX923, clearText},
		// AES-128-CTR ISO/IEC 9797-1 padding
		{"Od5pO4YprY9UqAxokeQo4A==", aes128Key, iv, paddings.ISO97971, clearText},
		// AES-192-CTR ISO/IEC 9797-1 padding
		{"kcakAFrfOQPVl7u035jYLw==", aes192Key, iv, paddings.ISO97971, clearText},
		// AES-256-CTR ISO/IEC 9797-1 padding
		{"fcy7eDqucP7lG1av6MVgvQ==", aes256Key, iv, paddings.ISO97971, clearText},
		// AES-128-CTR PKCS7 padding
		{"Od5pO4YprY9UqIpul+Iu5g==", aes128Key, iv, paddings.PKCS7, clearText},
		// AES-192-CTR PKCS7 padding
		{"kcakAFrfOQPVlz2y2Z7eKQ==", aes192Key, iv, paddings.PKCS7, clearText},
		// AES-256-CTR PKCS7 padding
		{"fcy7eDqucP7lG9Cp7sNmuw==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CTR-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := AesCTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestAesCTRISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// AES-128-CTR PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// AES-192-CTR PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// AES-256-CTR PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := AesCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := AesCTRDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleAesECBEncrypt() {
	encrypt, err := AesECBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: G4q6Xt8NyBS9Gi2rfgdleA==
}

func TestAesECBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// AES-128-ECB Zero padding
		{clearText, aes128Key, paddings.Zero, "G4q6Xt8NyBS9Gi2rfgdleA=="},
		// AES-192-ECB Zero padding
		{clearText, aes192Key, paddings.Zero, "JW3kOm2/oF2zB4uaZl41EQ=="},
		// AES-256-ECB Zero padding
		{clearText, aes256Key, paddings.Zero, "fGPDkFvsv58UHYxXlbeSQA=="},
		// AES-128-ECB ANSI X.923 padding
		{clearText, aes128Key, paddings.AnsiX923, "iUycGCq9LDb33ZZ5eBKmZg=="},
		// AES-192-ECB ANSI X.923 padding
		{clearText, aes192Key, paddings.AnsiX923, "wpFjQRmpDfLd0erw0s6+Zw=="},
		// AES-256-ECB ANSI X.923 padding
		{clearText, aes256Key, paddings.AnsiX923, "ZrtYnoD3zs2MFcTrdke0jg=="},
		// AES-128-ECB ISO/IEC 9797-1 padding
		{clearText, aes128Key, paddings.ISO97971, "LFq+YhVcR3NLWeX1SoUv+w=="},
		// AES-192-ECB ISO/IEC 9797-1 padding
		{clearText, aes192Key, paddings.ISO97971, "vrMSznj0zvojBprXuMXLUA=="},
		// AES-256-ECB ISO/IEC 9797-1 padding
		{clearText, aes256Key, paddings.ISO97971, "OTg2a5gyTaBOsr1wpI+I4A=="},
		// AES-128-ECB PKCS7 padding
		{clearText, aes128Key, paddings.PKCS7, "ErYDQkJwHpgIKp+FMKZ0yQ=="},
		// AES-192-ECB PKCS7 padding
		{clearText, aes192Key, paddings.PKCS7, "H/wisoDcYpEkgzExMLcofA=="},
		// AES-256-ECB PKCS7 padding
		{clearText, aes256Key, paddings.PKCS7, "nLyxDaKfWPdt+mXnZSWj5w=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := AesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleAesECBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("G4q6Xt8NyBS9Gi2rfgdleA==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := AesECBDecrypt(src, []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func TestAesECBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// AES-128-ECB Zero padding
		{"G4q6Xt8NyBS9Gi2rfgdleA==", aes128Key, paddings.Zero, clearText},
		// AES-192-ECB Zero padding
		{"JW3kOm2/oF2zB4uaZl41EQ==", aes192Key, paddings.Zero, clearText},
		// AES-256-ECB Zero padding
		{"fGPDkFvsv58UHYxXlbeSQA==", aes256Key, paddings.Zero, clearText},
		// AES-128-ECB ANSI X.923 padding
		{"iUycGCq9LDb33ZZ5eBKmZg==", aes128Key, paddings.AnsiX923, clearText},
		// AES-192-ECB ANSI X.923 padding
		{"wpFjQRmpDfLd0erw0s6+Zw==", aes192Key, paddings.AnsiX923, clearText},
		// AES-256-ECB ANSI X.923 padding
		{"ZrtYnoD3zs2MFcTrdke0jg==", aes256Key, paddings.AnsiX923, clearText},
		// AES-128-ECB ISO/IEC 9797-1 padding
		{"LFq+YhVcR3NLWeX1SoUv+w==", aes128Key, paddings.ISO97971, clearText},
		// AES-192-ECB ISO/IEC 9797-1 padding
		{"vrMSznj0zvojBprXuMXLUA==", aes192Key, paddings.ISO97971, clearText},
		// AES-256-ECB ISO/IEC 9797-1 padding
		{"OTg2a5gyTaBOsr1wpI+I4A==", aes256Key, paddings.ISO97971, clearText},
		// AES-128-ECB PKCS7 padding
		{"ErYDQkJwHpgIKp+FMKZ0yQ==", aes128Key, paddings.PKCS7, clearText},
		// AES-192-ECB PKCS7 padding
		{"H/wisoDcYpEkgzExMLcofA==", aes192Key, paddings.PKCS7, clearText},
		// AES-256-ECB PKCS7 padding
		{"nLyxDaKfWPdt+mXnZSWj5w==", aes256Key, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := AesECBDecrypt(src, v.Key, v.Mode)
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
		Mode      paddings.CipherPadding
	}{
		// AES-128-ECB PKCS7 padding
		{clearText, aes128Key, paddings.ISO10126},
		// AES-192-ECB PKCS7 padding
		{clearText, aes192Key, paddings.ISO10126},
		// AES-256-ECB PKCS7 padding
		{clearText, aes256Key, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := AesECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := AesECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleAesOFBEncrypt() {
	encrypt, err := AesOFBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: Od5pO4YprY9UqIxokeQo4A==
}

func TestAesOFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// AES-128-OFB Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "Od5pO4YprY9UqIxokeQo4A=="},
		// AES-192-OFB Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "kcakAFrfOQPVlzu035jYLw=="},
		// AES-256-OFB Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "fcy7eDqucP7lG9av6MVgvQ=="},
		// AES-128-OFB ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "Od5pO4YprY9UqIxokeQo5g=="},
		// AES-192-OFB ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "kcakAFrfOQPVlzu035jYKQ=="},
		// AES-256-OFB ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "fcy7eDqucP7lG9av6MVguw=="},
		// AES-128-OFB ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "Od5pO4YprY9UqAxokeQo4A=="},
		// AES-192-OFB ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "kcakAFrfOQPVl7u035jYLw=="},
		// AES-256-OFB ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "fcy7eDqucP7lG1av6MVgvQ=="},
		// AES-128-OFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "Od5pO4YprY9UqIpul+Iu5g=="},
		// AES-192-OFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "kcakAFrfOQPVlz2y2Z7eKQ=="},
		// AES-256-OFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "fcy7eDqucP7lG9Cp7sNmuw=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := AesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleAesOFBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("Od5pO4YprY9UqIxokeQo4A==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := AesOFBDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func TestAesOFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// AES-128-OFB Zero padding
		{"Od5pO4YprY9UqIxokeQo4A==", aes128Key, iv, paddings.Zero, clearText},
		// AES-192-OFB Zero padding
		{"kcakAFrfOQPVlzu035jYLw==", aes192Key, iv, paddings.Zero, clearText},
		// AES-256-OFB Zero padding
		{"fcy7eDqucP7lG9av6MVgvQ==", aes256Key, iv, paddings.Zero, clearText},
		// AES-128-OFB ANSI X.923 padding
		{"Od5pO4YprY9UqIxokeQo5g==", aes128Key, iv, paddings.AnsiX923, clearText},
		// AES-192-OFB ANSI X.923 padding
		{"kcakAFrfOQPVlzu035jYKQ==", aes192Key, iv, paddings.AnsiX923, clearText},
		// AES-256-OFB ANSI X.923 padding
		{"fcy7eDqucP7lG9av6MVguw==", aes256Key, iv, paddings.AnsiX923, clearText},
		// AES-128-OFB ISO/IEC 9797-1 padding
		{"Od5pO4YprY9UqAxokeQo4A==", aes128Key, iv, paddings.ISO97971, clearText},
		// AES-192-OFB ISO/IEC 9797-1 padding
		{"kcakAFrfOQPVl7u035jYLw==", aes192Key, iv, paddings.ISO97971, clearText},
		// AES-256-OFB ISO/IEC 9797-1 padding
		{"fcy7eDqucP7lG1av6MVgvQ==", aes256Key, iv, paddings.ISO97971, clearText},
		// AES-128-OFB PKCS7 padding
		{"Od5pO4YprY9UqIpul+Iu5g==", aes128Key, iv, paddings.PKCS7, clearText},
		// AES-192-OFB PKCS7 padding
		{"kcakAFrfOQPVlz2y2Z7eKQ==", aes192Key, iv, paddings.PKCS7, clearText},
		// AES-256-OFB PKCS7 padding
		{"fcy7eDqucP7lG9Cp7sNmuw==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-OFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := AesOFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestAesOFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// AES-128-OFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// AES-192-OFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// AES-256-OFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := AesOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := AesOFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleAesGCMEncrypt() {
	clearText := []byte("TrumanWong")
	key := []byte("1234567812345678")
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		return
	}

	password, err := AesGCMEncrypt(clearText, key, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	ret, err := AesGCMDecrypt(password, key, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(ret))
	// Output: TrumanWong
}

func TestAesGCMEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
	}{
		// AES-128-GCM
		{clearText, aes128Key},
		// AES-192-GCM
		{clearText, aes192Key},
		// AES-256-GCM
		{clearText, aes256Key},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("AES-GCM"), func(t *testing.T) {
			nonce := make([]byte, 12)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				fmt.Println(err)
				return
			}
			password, err := AesGCMEncrypt(v.ClearText, v.Key, nonce)
			assert.NoError(t, err)

			ret, err := AesGCMDecrypt(password, v.Key, nonce)
			assert.NoError(t, err)
			assert.Equal(t, string(clearText), string(ret))
		})
	}
}
