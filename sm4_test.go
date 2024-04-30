package cryptogo

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"testing"
)

func ExampleSm4CBCEncrypt() {
	encrypt, err := Sm4CBCEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: 6pWZk9lLpz4vFgzByqP+Sg==
}

func ExampleSm4CBCDecrypt() {
	src, err := base64.StdEncoding.DecodeString("6pWZk9lLpz4vFgzByqP+Sg==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4CBCDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func ExampleSm4CFBEncrypt() {
	encrypt, err := Sm4CFBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: vBEQQjHDCbaSpz60W+0BFg==
}

func ExampleSm4CFBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("vBEQQjHDCbaSpz60W+0BFg==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4CFBDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func ExampleSm4OFBEncrypt() {
	encrypt, err := Sm4OFBEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: vBEQQjHDCbaSpz60W+0BFg==
}

func ExampleSm4OFBDecrypt() {
	src, err := base64.StdEncoding.DecodeString("vBEQQjHDCbaSpz60W+0BFg==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4OFBDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func ExampleSm4CTREncrypt() {
	encrypt, err := Sm4CTREncrypt([]byte("TrumanWong"), []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: vBEQQjHDCbaSpz60W+0BFg==
}

func ExampleSm4CTRDecrypt() {
	src, err := base64.StdEncoding.DecodeString("vBEQQjHDCbaSpz60W+0BFg==")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4CTRDecrypt(src, []byte("1234567812345678"), []byte("1234567812345678"), paddings.PKCS7)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func ExampleSm4CCMEncrypt() {
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	encrypt, err := Sm4CCMEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: 7sZG+aVsUQiK75ZZOfNkyJ4H4cihvssY9U0=
}

func ExampleSm4CCMDecrypt() {
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	src, err := base64.StdEncoding.DecodeString("7sZG+aVsUQiK75ZZOfNkyJ4H4cihvssY9U0=")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4CCMDecrypt(src, []byte("1234567812345678"), nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func ExampleSm4GCMEncrypt() {
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	encrypt, err := Sm4GCMEncrypt([]byte("TrumanWong"), []byte("1234567812345678"), nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
	// Output: sMbUUdfBMAyIql9gNOIX0uKEiPPo3OwyiaI=
}

func ExampleSm4GCMDecrypt() {
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	src, err := base64.StdEncoding.DecodeString("sMbUUdfBMAyIql9gNOIX0uKEiPPo3OwyiaI=")
	if err != nil {
		fmt.Println(err)
		return
	}
	password, err := Sm4GCMDecrypt(src, []byte("1234567812345678"), nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(password))
	// Output: TrumanWong
}

func TestSm4CBCEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "1HBvHO5pbwwfpkQG5jr6OA=="},
		// ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "6VHCoDRN0INKYSlP8Zb3gQ=="},
		// ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "U0TwWU5LzIZEaSfjfayAgw=="},
		// ISO10126 padding
		//{clearText, aes128Key, iv, paddings.ISO10126, "GTlBtaPryq72bgNMChulXg=="},
		// PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "6pWZk9lLpz4vFgzByqP+Sg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := Sm4CBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4CBCDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Zero padding
		{"1HBvHO5pbwwfpkQG5jr6OA==", aes128Key, iv, paddings.Zero, clearText},
		// ANSI X.923 padding
		{"6VHCoDRN0INKYSlP8Zb3gQ==", aes128Key, iv, paddings.AnsiX923, clearText},
		// ISO/IEC 9797-1 padding
		{"U0TwWU5LzIZEaSfjfayAgw==", aes128Key, iv, paddings.ISO97971, clearText},
		// ISO10126 padding
		{"GTlBtaPryq72bgNMChulXg==", aes128Key, iv, paddings.ISO10126, clearText},
		// PKCS7 padding
		{"6pWZk9lLpz4vFgzByqP+Sg==", aes128Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4CBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestSm4CFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "vBEQQjHDCbaSpziyXesHEA=="},
		// ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "vBEQQjHDCbaSpziyXesHFg=="},
		// ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "vBEQQjHDCbaSp7iyXesHEA=="},
		// ISO10126 padding
		//{clearText, aes128Key, iv, paddings.ISO10126, "vBEQQjHDCbaSp5owpuLxFg=="},
		// PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "vBEQQjHDCbaSpz60W+0BFg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := Sm4CFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4CFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Zero padding
		{"vBEQQjHDCbaSpziyXesHEA==", aes128Key, iv, paddings.Zero, clearText},
		// ANSI X.923 padding
		{"vBEQQjHDCbaSpziyXesHFg==", aes128Key, iv, paddings.AnsiX923, clearText},
		// ISO/IEC 9797-1 padding
		{"vBEQQjHDCbaSp7iyXesHEA==", aes128Key, iv, paddings.ISO97971, clearText},
		// ISO10126 padding
		{"vBEQQjHDCbaSp5owpuLxFg==", aes128Key, iv, paddings.ISO10126, clearText},
		// PKCS7 padding
		{"vBEQQjHDCbaSpz60W+0BFg==", aes128Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4CFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestSm4OFBEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "vBEQQjHDCbaSpziyXesHEA=="},
		// ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "vBEQQjHDCbaSpziyXesHFg=="},
		// ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "vBEQQjHDCbaSp7iyXesHEA=="},
		// ISO10126 padding
		//{clearText, aes128Key, iv, paddings.ISO10126, "vBEQQjHDCbaSp5owpuLxFg=="},
		// PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "vBEQQjHDCbaSpz60W+0BFg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := Sm4OFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4OFBDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Zero padding
		{"vBEQQjHDCbaSpziyXesHEA==", aes128Key, iv, paddings.Zero, clearText},
		// ANSI X.923 padding
		{"vBEQQjHDCbaSpziyXesHFg==", aes128Key, iv, paddings.AnsiX923, clearText},
		// ISO/IEC 9797-1 padding
		{"vBEQQjHDCbaSp7iyXesHEA==", aes128Key, iv, paddings.ISO97971, clearText},
		// ISO10126 padding
		{"vBEQQjHDCbaSp5owpuLxFg==", aes128Key, iv, paddings.ISO10126, clearText},
		// PKCS7 padding
		{"vBEQQjHDCbaSpz60W+0BFg==", aes128Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4OFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestSm4CTREncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	iv := []byte("1234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		IV        []byte
		Mode      paddings.CipherPadding
		Expected  string
	}{
		// Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "vBEQQjHDCbaSpziyXesHEA=="},
		// ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "vBEQQjHDCbaSpziyXesHFg=="},
		// ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "vBEQQjHDCbaSp7iyXesHEA=="},
		// ISO10126 padding
		//{clearText, aes128Key, iv, paddings.ISO10126, "vBEQQjHDCbaSp5owpuLxFg=="},
		// PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "vBEQQjHDCbaSpz60W+0BFg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := Sm4CTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4CTRDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	iv := []byte("1234567812345678")
	tests := []struct {
		Encrypt  string
		Key      []byte
		IV       []byte
		Mode     paddings.CipherPadding
		Expected string
	}{
		// Zero padding
		{"vBEQQjHDCbaSpziyXesHEA==", aes128Key, iv, paddings.Zero, clearText},
		// ANSI X.923 padding
		{"vBEQQjHDCbaSpziyXesHFg==", aes128Key, iv, paddings.AnsiX923, clearText},
		// ISO/IEC 9797-1 padding
		{"vBEQQjHDCbaSp7iyXesHEA==", aes128Key, iv, paddings.ISO97971, clearText},
		// ISO10126 padding
		{"vBEQQjHDCbaSp5owpuLxFg==", aes128Key, iv, paddings.ISO10126, clearText},
		// PKCS7 padding
		{"vBEQQjHDCbaSpz60W+0BFg==", aes128Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4CTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestSm4CCMEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	//nonce := make([]byte, 12)
	//_, err := io.ReadFull(rand.Reader, nonce)
	//assert.NoError(t, err)
	//fmt.Printf("|%s|", base64.StdEncoding.EncodeToString(nonce))
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Nonce     []byte
		Expected  string
	}{
		{clearText, aes128Key, nonce, "7sZG+aVsUQiK75ZZOfNkyJ4H4cihvssY9U0="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CCM"), func(t *testing.T) {
			password, err := Sm4CCMEncrypt(v.ClearText, v.Key, v.Nonce)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4CCMDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Nonce    []byte
		Expected string
	}{
		{"7sZG+aVsUQiK75ZZOfNkyJ4H4cihvssY9U0=", aes128Key, nonce, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CCM"), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4CCMDecrypt(src, v.Key, v.Nonce)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestSm4GCMEncrypt(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")

	//nonce := make([]byte, 12)
	//_, err := io.ReadFull(rand.Reader, nonce)
	//assert.NoError(t, err)
	//fmt.Printf("|%s|", base64.StdEncoding.EncodeToString(nonce))
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Nonce     []byte
		Expected  string
	}{
		{clearText, aes128Key, nonce, "sMbUUdfBMAyIql9gNOIX0uKEiPPo3OwyiaI="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CCM"), func(t *testing.T) {
			password, err := Sm4GCMEncrypt(v.ClearText, v.Key, v.Nonce)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestSm4GCMDecrypt(t *testing.T) {
	clearText := "TrumanWong"
	aes128Key := []byte("1234567812345678")
	nonce, _ := base64.StdEncoding.DecodeString("OChmI6qkGVC16qbY")
	tests := []struct {
		Encrypt  string
		Key      []byte
		Nonce    []byte
		Expected string
	}{
		{"sMbUUdfBMAyIql9gNOIX0uKEiPPo3OwyiaI=", aes128Key, nonce, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("SM4-CCM"), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := Sm4GCMDecrypt(src, v.Key, v.Nonce)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}
