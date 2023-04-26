package cryptogo

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"testing"
)

func ExampleBlowfishCBCEncrypt() {
	encrypt, err := BlowfishCBCEncrypt([]byte("TrumanWong"), []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: 9EOZcxBiUN1RF9MIP4DFyA==
}

func TestBlowfishCBCEncrypt(t *testing.T) {
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
		// Triple-CBC Zero padding
		{clearText, key, iv, paddings.Zero, "9EOZcxBiUN1RF9MIP4DFyA=="},
		// Triple-CBC ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "9EOZcxBiUN2ilcsytjfS1w=="},
		// Triple-CBC ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "9EOZcxBiUN3OCD1lNyvmVg=="},
		// Triple-CBC PKCS5padding
		{clearText, key, iv, paddings.PKCS5, "9EOZcxBiUN0KdlJJdzUnEQ=="},
		// Triple-CBC PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "9EOZcxBiUN0KdlJJdzUnEQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleBlowfishCBCDecrypt() {
	encrypt, err := base64.StdEncoding.DecodeString("9EOZcxBiUN1RF9MIP4DFyA==")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypt, err := BlowfishCBCDecrypt(encrypt, []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypt))
	// Output: TrumanWong
}

func TestBlowfishCBCDecrypt(t *testing.T) {
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
		// Triple-CBC Zero padding
		{"9EOZcxBiUN1RF9MIP4DFyA==", key, iv, paddings.Zero, clearText},
		// Triple-CBC ANSI X.923 padding
		{"9EOZcxBiUN2ilcsytjfS1w==", key, iv, paddings.AnsiX923, clearText},
		// Triple-CBC ISO/IEC 9797-1 padding
		{"9EOZcxBiUN3OCD1lNyvmVg==", key, iv, paddings.ISO97971, clearText},
		// Triple-CBC PKCS7 padding
		{"9EOZcxBiUN0KdlJJdzUnEQ==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := BlowfishCBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestBlowfishCBCISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-CBC ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := BlowfishCBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleBlowfishCFBEncrypt() {
	encrypt, err := BlowfishCFBEncrypt([]byte("TrumanWong"), []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: QM6mpzZJDT2mBu4k1NdGPA==
}

func TestBlowfishCFBEncrypt(t *testing.T) {
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
		// Triple-CFB Zero padding
		{clearText, key, iv, paddings.Zero, "QM6mpzZJDT2mBu4k1NdGPA=="},
		// Triple-CFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "QM6mpzZJDT2mBu4k1NdGOg=="},
		// Triple-CFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "QM6mpzZJDT2mBm4k1NdGPA=="},
		// Triple-CFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "QM6mpzZJDT2mBugi0tFAOg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleBlowfishCFBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("QM6mpzZJDT2mBu4k1NdGPA==")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypt, err := BlowfishCFBDecrypt(src, []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypt))
	// Output: TrumanWong
}

func TestBlowfishCFBDecrypt(t *testing.T) {
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
		// Triple-CFB Zero padding
		{"QM6mpzZJDT2mBu4k1NdGPA==", key, iv, paddings.Zero, clearText},
		// Triple-CFB ANSI X.923 padding
		{"QM6mpzZJDT2mBu4k1NdGOg==", key, iv, paddings.AnsiX923, clearText},
		// Triple-CFB ISO/IEC 9797-1 padding
		{"QM6mpzZJDT2mBm4k1NdGPA==", key, iv, paddings.ISO97971, clearText},
		// Triple-CFB PKCS7 padding
		{"QM6mpzZJDT2mBugi0tFAOg==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := BlowfishCFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestBlowfishCFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-CFB ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := BlowfishCFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleBlowfishCTREncrypt() {
	encrypt, err := BlowfishCTREncrypt([]byte("TrumanWong"), []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: QM6mpzZJDT27xwEkDxgIGQ==
}

func TestBlowfishCTREncrypt(t *testing.T) {
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
		// Triple-CTR Zero padding
		{clearText, key, iv, paddings.Zero, "QM6mpzZJDT27xwEkDxgIGQ=="},
		// Triple-CTR ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "QM6mpzZJDT27xwEkDxgIHw=="},
		// Triple-CTR ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "QM6mpzZJDT27x4EkDxgIGQ=="},
		// Triple-CTR PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "QM6mpzZJDT27xwciCR4OHw=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleBlowfishCTRDecrypt() {
	src, err := base64.StdEncoding.DecodeString("QM6mpzZJDT27xwEkDxgIGQ==")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypt, err := BlowfishCTRDecrypt(src, []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypt))
	// Output: TrumanWong
}

func TestBlowfishCTRDecrypt(t *testing.T) {
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
		// Triple-CTR Zero padding
		{"QM6mpzZJDT27xwEkDxgIGQ==", key, iv, paddings.Zero, clearText},
		// Triple-CTR ANSI X.923 padding
		{"QM6mpzZJDT27xwEkDxgIHw==", key, iv, paddings.AnsiX923, clearText},
		// Triple-CTR ISO/IEC 9797-1 padding
		{"QM6mpzZJDT27x4EkDxgIGQ==", key, iv, paddings.ISO97971, clearText},
		// Triple-CTR PKCS7 padding
		{"QM6mpzZJDT27xwciCR4OHw==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CTR-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := BlowfishCTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestBlowfishCTRISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-CTR ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := BlowfishCTRDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleBlowfishECBEncrypt() {
	encrypt, err := BlowfishECBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: oCuapqeOZtmwqM4VwEXz2w==
}

func TestBlowfishECBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Triple-ECB Zero padding
		{clearText, key, paddings.Zero, "oCuapqeOZtmwqM4VwEXz2w=="},
		// Triple-ECB ANSI X.923 padding
		{clearText, key, paddings.AnsiX923, "oCuapqeOZtmyTJLHUorLbw=="},
		// Triple-ECB ISO/IEC 9797-1 padding
		{clearText, key, paddings.ISO97971, "oCuapqeOZtlzyvlSHZb5+g=="},
		// Triple-ECB PKCS7 padding
		{clearText, key, paddings.PKCS7, "oCuapqeOZtmRwRCUYFn4Vg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleBlowfishECBDecrypt() {
	encrypt, err := base64.StdEncoding.DecodeString("oCuapqeOZtmwqM4VwEXz2w==")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypt, err := BlowfishECBDecrypt(encrypt, []byte("1234567812345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypt))
	// Output: TrumanWong
}

func TestBlowfishECBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	key := []byte("123456781234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Triple-ECB Zero padding
		{"oCuapqeOZtmwqM4VwEXz2w==", key, paddings.Zero, clearText},
		// Triple-ECB ANSI X.923 padding
		{"oCuapqeOZtmyTJLHUorLbw==", key, paddings.AnsiX923, clearText},
		// Triple-ECB ISO/IEC 9797-1 padding
		{"oCuapqeOZtlzyvlSHZb5+g==", key, paddings.ISO97971, clearText},
		// Triple-ECB PKCS7 padding
		{"oCuapqeOZtmRwRCUYFn4Vg==", key, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := BlowfishECBDecrypt(src, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestBlowfishECBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-ECB ISO 10126 padding
		{clearText, key, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := BlowfishECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func ExampleBlowfishOFBEncrypt() {
	encrypt, err := BlowfishOFBEncrypt([]byte("TrumanWong"), []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: QM6mpzZJDT3SLilrXziq/Q==
}

func TestBlowfishOFBEncrypt(t *testing.T) {
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
		// Triple-OFB Zero padding
		{clearText, key, iv, paddings.Zero, "QM6mpzZJDT3SLilrXziq/Q=="},
		// Triple-OFB ANSI X.923 padding
		{clearText, key, iv, paddings.AnsiX923, "QM6mpzZJDT3SLilrXziq+w=="},
		// Triple-OFB ISO/IEC 9797-1 padding
		{clearText, key, iv, paddings.ISO97971, "QM6mpzZJDT3SLqlrXziq/Q=="},
		// Triple-OFB PKCS7 padding
		{clearText, key, iv, paddings.PKCS7, "QM6mpzZJDT3SLi9tWT6s+w=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func ExampleBlowfishOFBDecrypt() {
	encrypt, err := base64.StdEncoding.DecodeString("QM6mpzZJDT3SLilrXziq/Q==")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypt, err := BlowfishOFBDecrypt(encrypt, []byte("123456781234567812345678"), []byte("12345678"), paddings.Zero)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypt))
	// Output: TrumanWong
}

func TestBlowfishOFBDecrypt(t *testing.T) {
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
		// Triple-OFB Zero padding
		{"QM6mpzZJDT3SLilrXziq/Q==", key, iv, paddings.Zero, clearText},
		// Triple-OFB ANSI X.923 padding
		{"QM6mpzZJDT3SLilrXziq+w==", key, iv, paddings.AnsiX923, clearText},
		// Triple-OFB ISO/IEC 9797-1 padding
		{"QM6mpzZJDT3SLqlrXziq/Q==", key, iv, paddings.ISO97971, clearText},
		// Triple-OFB PKCS7 padding
		{"QM6mpzZJDT3SLi9tWT6s+w==", key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-OFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := BlowfishOFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestBlowfishOFBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	key := []byte("123456781234567812345678")
	iv := []byte("12345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
	}{
		// Triple-OFB ISO 10126 padding
		{clearText, key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Blowfish-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := BlowfishOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := BlowfishOFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
