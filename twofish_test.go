package cryptogo

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trumanwong/cryptogo/paddings"
	"testing"
)

func TestTwofishCBCEncrypt(t *testing.T) {
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
		// Twofish-128-CBC Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "JoOk/hwxZrNVUV3WRiFKXQ=="},
		// Twofish-192-CBC Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "On2Cyo4Kk8iiHAx3+CDzEw=="},
		// Twofish-256-CBC Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "1GnMq7iFDZmTaYgqPZ6SiA=="},
		// Twofish-128-CBC ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "hCgoyy4AnuW1QWQspiveHA=="},
		// Twofish-192-CBC ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "LCO+K6BQye55Nz9Z3NyD1A=="},
		// Twofish-256-CBC ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "5/PANNJ3IfBF/ilZKqikng=="},
		// Twofish-128-CBC ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "ntjGTfyfytirxxvDMfjuSg=="},
		// Twofish-192-CBC ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "WKYYtoRcBpYMw5fnStF5RQ=="},
		// Twofish-256-CBC ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "g9yYPoMZAqCqqwy+3cmQIA=="},
		// Twofish-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "sspf2hVsnxh3DvEgggEBBQ=="},
		// Twofish-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "6RCKgHMoXH6QbLoQvJF1ig=="},
		// Twofish-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "hVVtxEdr75IzH8g4Od2v6g=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTwofishCBCDecrypt(t *testing.T) {
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
		// Twofish-128-CBC Zero padding
		{"JoOk/hwxZrNVUV3WRiFKXQ==", aes128Key, iv, paddings.Zero, clearText},
		// Twofish-192-CBC Zero padding
		{"On2Cyo4Kk8iiHAx3+CDzEw==", aes192Key, iv, paddings.Zero, clearText},
		// Twofish-256-CBC Zero padding
		{"1GnMq7iFDZmTaYgqPZ6SiA==", aes256Key, iv, paddings.Zero, clearText},
		// Twofish-128-CBC ANSI X.923 padding
		{"hCgoyy4AnuW1QWQspiveHA==", aes128Key, iv, paddings.AnsiX923, clearText},
		// Twofish-192-CBC ANSI X.923 padding
		{"LCO+K6BQye55Nz9Z3NyD1A==", aes192Key, iv, paddings.AnsiX923, clearText},
		// Twofish-256-CBC ANSI X.923 padding
		{"5/PANNJ3IfBF/ilZKqikng==", aes256Key, iv, paddings.AnsiX923, clearText},
		// Twofish-128-CBC ISO/IEC 9797-1 padding
		{"ntjGTfyfytirxxvDMfjuSg==", aes128Key, iv, paddings.ISO97971, clearText},
		// Twofish-192-CBC ISO/IEC 9797-1 padding
		{"WKYYtoRcBpYMw5fnStF5RQ==", aes192Key, iv, paddings.ISO97971, clearText},
		// Twofish-256-CBC ISO/IEC 9797-1 padding
		{"g9yYPoMZAqCqqwy+3cmQIA==", aes256Key, iv, paddings.ISO97971, clearText},
		// Twofish-128-CBC PKCS7 padding
		{"sspf2hVsnxh3DvEgggEBBQ==", aes128Key, iv, paddings.PKCS7, clearText},
		// Twofish-192-CBC PKCS7 padding
		{"6RCKgHMoXH6QbLoQvJF1ig==", aes192Key, iv, paddings.PKCS7, clearText},
		// Twofish-256-CBC PKCS7 padding
		{"hVVtxEdr75IzH8g4Od2v6g==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CBC-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TwofishCBCDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTwofishCBCISO10126(t *testing.T) {
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
		// Twofish-128-CBC PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// Twofish-192-CBC PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// Twofish-256-CBC PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CBC-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCBCEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TwofishCBCDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTwofishCFBEncrypt(t *testing.T) {
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
		// Twofish-128-CFB Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "UpJQg/lduy/JCUSvAf/oug=="},
		// Twofish-192-CFB Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "bqsQl68w2xLwV4RJNZAt/A=="},
		// Twofish-256-CFB Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "rxORmBL5zdY4MAwyNHaTaA=="},
		// Twofish-128-CFB ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "UpJQg/lduy/JCUSvAf/ovA=="},
		// Twofish-192-CFB ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "bqsQl68w2xLwV4RJNZAt+g=="},
		// Twofish-256-CFB ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "rxORmBL5zdY4MAwyNHaTbg=="},
		// Twofish-128-CFB ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "UpJQg/lduy/JCcSvAf/oug=="},
		// Twofish-192-CFB ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "bqsQl68w2xLwVwRJNZAt/A=="},
		// Twofish-256-CFB ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "rxORmBL5zdY4MIwyNHaTaA=="},
		// Twofish-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "UpJQg/lduy/JCUKpB/nuvA=="},
		// Twofish-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "bqsQl68w2xLwV4JPM5Yr+g=="},
		// Twofish-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "rxORmBL5zdY4MAo0MnCVbg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTwofishCFBDecrypt(t *testing.T) {
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
		// Twofish-128-CFB Zero padding
		{"UpJQg/lduy/JCUSvAf/oug==", aes128Key, iv, paddings.Zero, clearText},
		// Twofish-192-CFB Zero padding
		{"bqsQl68w2xLwV4RJNZAt/A==", aes192Key, iv, paddings.Zero, clearText},
		// Twofish-256-CFB Zero padding
		{"rxORmBL5zdY4MAwyNHaTaA==", aes256Key, iv, paddings.Zero, clearText},
		// Twofish-128-CFB ANSI X.923 padding
		{"UpJQg/lduy/JCUSvAf/ovA==", aes128Key, iv, paddings.AnsiX923, clearText},
		// Twofish-192-CFB ANSI X.923 padding
		{"bqsQl68w2xLwV4RJNZAt+g==", aes192Key, iv, paddings.AnsiX923, clearText},
		// Twofish-256-CFB ANSI X.923 padding
		{"rxORmBL5zdY4MAwyNHaTbg==", aes256Key, iv, paddings.AnsiX923, clearText},
		// Twofish-128-CFB ISO/IEC 9797-1 padding
		{"UpJQg/lduy/JCcSvAf/oug==", aes128Key, iv, paddings.ISO97971, clearText},
		// Twofish-192-CFB ISO/IEC 9797-1 padding
		{"bqsQl68w2xLwVwRJNZAt/A==", aes192Key, iv, paddings.ISO97971, clearText},
		// Twofish-256-CFB ISO/IEC 9797-1 padding
		{"rxORmBL5zdY4MIwyNHaTaA==", aes256Key, iv, paddings.ISO97971, clearText},
		// Twofish-128-CFB PKCS7 padding
		{"UpJQg/lduy/JCUKpB/nuvA==", aes128Key, iv, paddings.PKCS7, clearText},
		// Twofish-192-CFB PKCS7 padding
		{"bqsQl68w2xLwV4JPM5Yr+g==", aes192Key, iv, paddings.PKCS7, clearText},
		// Twofish-256-CFB PKCS7 padding
		{"rxORmBL5zdY4MAo0MnCVbg==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TwofishCFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTwofishCFBISO10126(t *testing.T) {
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
		// Twofish-128-CFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// Twofish-192-CFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// Twofish-256-CFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CFB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TwofishCFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTwofishCTREncrypt(t *testing.T) {
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
		// Twofish-128-CTR Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "UpJQg/lduy/JCUSvAf/oug=="},
		// Twofish-192-CTR Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "bqsQl68w2xLwV4RJNZAt/A=="},
		// Twofish-256-CTR Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "rxORmBL5zdY4MAwyNHaTaA=="},
		// Twofish-128-CTR ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "UpJQg/lduy/JCUSvAf/ovA=="},
		// Twofish-192-CTR ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "bqsQl68w2xLwV4RJNZAt+g=="},
		// Twofish-256-CTR ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "rxORmBL5zdY4MAwyNHaTbg=="},
		// Twofish-128-CTR ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "UpJQg/lduy/JCcSvAf/oug=="},
		// Twofish-192-CTR ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "bqsQl68w2xLwVwRJNZAt/A=="},
		// Twofish-256-CTR ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "rxORmBL5zdY4MIwyNHaTaA=="},
		// Twofish-128-CTR PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "UpJQg/lduy/JCUKpB/nuvA=="},
		// Twofish-192-CTR PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "bqsQl68w2xLwV4JPM5Yr+g=="},
		// Twofish-256-CTR PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "rxORmBL5zdY4MAo0MnCVbg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTwofishCTRDecrypt(t *testing.T) {
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
		// Twofish-128-CTR Zero padding
		{"UpJQg/lduy/JCUSvAf/oug==", aes128Key, iv, paddings.Zero, clearText},
		// Twofish-192-CTR Zero padding
		{"bqsQl68w2xLwV4RJNZAt/A==", aes192Key, iv, paddings.Zero, clearText},
		// Twofish-256-CTR Zero padding
		{"rxORmBL5zdY4MAwyNHaTaA==", aes256Key, iv, paddings.Zero, clearText},
		// Twofish-128-CTR ANSI X.923 padding
		{"UpJQg/lduy/JCUSvAf/ovA==", aes128Key, iv, paddings.AnsiX923, clearText},
		// Twofish-192-CTR ANSI X.923 padding
		{"bqsQl68w2xLwV4RJNZAt+g==", aes192Key, iv, paddings.AnsiX923, clearText},
		// Twofish-256-CTR ANSI X.923 padding
		{"rxORmBL5zdY4MAwyNHaTbg==", aes256Key, iv, paddings.AnsiX923, clearText},
		// Twofish-128-CTR ISO/IEC 9797-1 padding
		{"UpJQg/lduy/JCcSvAf/oug==", aes128Key, iv, paddings.ISO97971, clearText},
		// Twofish-192-CTR ISO/IEC 9797-1 padding
		{"bqsQl68w2xLwVwRJNZAt/A==", aes192Key, iv, paddings.ISO97971, clearText},
		// Twofish-256-CTR ISO/IEC 9797-1 padding
		{"rxORmBL5zdY4MIwyNHaTaA==", aes256Key, iv, paddings.ISO97971, clearText},
		// Twofish-128-CTR PKCS7 padding
		{"UpJQg/lduy/JCUKpB/nuvA==", aes128Key, iv, paddings.PKCS7, clearText},
		// Twofish-192-CTR PKCS7 padding
		{"bqsQl68w2xLwV4JPM5Yr+g==", aes192Key, iv, paddings.PKCS7, clearText},
		// Twofish-256-CTR PKCS7 padding
		{"rxORmBL5zdY4MAo0MnCVbg==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CTR-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TwofishCTRDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTwofishCTRISO10126(t *testing.T) {
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
		// Twofish-128-CTR PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// Twofish-192-CTR PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// Twofish-256-CTR PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-CTR-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishCTREncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TwofishCTRDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTwofishECBEncrypt(t *testing.T) {
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
		// Twofish-128-ECB Zero padding
		{clearText, aes128Key, paddings.Zero, "175vuPPAssia62+VCMHQ8g=="},
		// Twofish-192-ECB Zero padding
		{clearText, aes192Key, paddings.Zero, "6KISaACBmR2j3Tw7KQfEEw=="},
		// Twofish-256-ECB Zero padding
		{clearText, aes256Key, paddings.Zero, "iHQhIQ3sCg6Q9s2qPiNp9A=="},
		// Twofish-128-ECB ANSI X.923 padding
		{clearText, aes128Key, paddings.AnsiX923, "fyjHajYKqS8yVsLmH1veGg=="},
		// Twofish-192-ECB ANSI X.923 padding
		{clearText, aes192Key, paddings.AnsiX923, "ri1I9QenCisuBifsonSZzQ=="},
		// Twofish-256-ECB ANSI X.923 padding
		{clearText, aes256Key, paddings.AnsiX923, "yAxj0+WCotk3x0arBjqxSw=="},
		// Twofish-128-ECB ISO/IEC 9797-1 padding
		{clearText, aes128Key, paddings.ISO97971, "y03OgNE1zT4faHur1+X36Q=="},
		// Twofish-192-ECB ISO/IEC 9797-1 padding
		{clearText, aes192Key, paddings.ISO97971, "rtd2IejNxOVyXnECLlb01A=="},
		// Twofish-256-ECB ISO/IEC 9797-1 padding
		{clearText, aes256Key, paddings.ISO97971, "OTKyj99tvbavkSTSaQbnMQ=="},
		// Twofish-128-ECB PKCS7 padding
		{clearText, aes128Key, paddings.PKCS7, "bwKdPs+B9gsUeyVhw+e32w=="},
		// Twofish-192-ECB PKCS7 padding
		{clearText, aes192Key, paddings.PKCS7, "82ja1furRYbQQQrn4aqGMg=="},
		// Twofish-256-ECB PKCS7 padding
		{clearText, aes256Key, paddings.PKCS7, "8a0K41DzLClNmGtrcxEJmQ=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTwofishECBDecrypt(t *testing.T) {
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
		// Twofish-128-ECB Zero padding
		{"175vuPPAssia62+VCMHQ8g==", aes128Key, paddings.Zero, clearText},
		// Twofish-192-ECB Zero padding
		{"6KISaACBmR2j3Tw7KQfEEw==", aes192Key, paddings.Zero, clearText},
		// Twofish-256-ECB Zero padding
		{"iHQhIQ3sCg6Q9s2qPiNp9A==", aes256Key, paddings.Zero, clearText},
		// Twofish-128-ECB ANSI X.923 padding
		{"fyjHajYKqS8yVsLmH1veGg==", aes128Key, paddings.AnsiX923, clearText},
		// Twofish-192-ECB ANSI X.923 padding
		{"ri1I9QenCisuBifsonSZzQ==", aes192Key, paddings.AnsiX923, clearText},
		// Twofish-256-ECB ANSI X.923 padding
		{"yAxj0+WCotk3x0arBjqxSw==", aes256Key, paddings.AnsiX923, clearText},
		// Twofish-128-ECB ISO/IEC 9797-1 padding
		{"y03OgNE1zT4faHur1+X36Q==", aes128Key, paddings.ISO97971, clearText},
		// Twofish-192-ECB ISO/IEC 9797-1 padding
		{"rtd2IejNxOVyXnECLlb01A==", aes192Key, paddings.ISO97971, clearText},
		// Twofish-256-ECB ISO/IEC 9797-1 padding
		{"OTKyj99tvbavkSTSaQbnMQ==", aes256Key, paddings.ISO97971, clearText},
		// Twofish-128-ECB PKCS7 padding
		{"bwKdPs+B9gsUeyVhw+e32w==", aes128Key, paddings.PKCS7, clearText},
		// Twofish-192-ECB PKCS7 padding
		{"82ja1furRYbQQQrn4aqGMg==", aes192Key, paddings.PKCS7, clearText},
		// Twofish-256-ECB PKCS7 padding
		{"8a0K41DzLClNmGtrcxEJmQ==", aes256Key, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-ECB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TwofishECBDecrypt(src, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTwofishECBISO10126(t *testing.T) {
	clearText := []byte("TrumanWong")
	aes128Key := []byte("1234567812345678")
	aes192Key := []byte("123456781234567812345678")
	aes256Key := []byte("12345678123456781234567812345678")
	tests := []struct {
		ClearText []byte
		Key       []byte
		Mode      paddings.CipherPadding
	}{
		// Twofish-128-ECB PKCS7 padding
		{clearText, aes128Key, paddings.ISO10126},
		// Twofish-192-ECB PKCS7 padding
		{clearText, aes192Key, paddings.ISO10126},
		// Twofish-256-ECB PKCS7 padding
		{clearText, aes256Key, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-ECB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishECBEncrypt(v.ClearText, v.Key, v.Mode)
			assert.NoError(t, err)

			ret, err := TwofishECBDecrypt(password, v.Key, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}

func TestTwofishOFBEncrypt(t *testing.T) {
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
		// Twofish-128-OFB Zero padding
		{clearText, aes128Key, iv, paddings.Zero, "UpJQg/lduy/JCUSvAf/oug=="},
		// Twofish-192-OFB Zero padding
		{clearText, aes192Key, iv, paddings.Zero, "bqsQl68w2xLwV4RJNZAt/A=="},
		// Twofish-256-OFB Zero padding
		{clearText, aes256Key, iv, paddings.Zero, "rxORmBL5zdY4MAwyNHaTaA=="},
		// Twofish-128-OFB ANSI X.923 padding
		{clearText, aes128Key, iv, paddings.AnsiX923, "UpJQg/lduy/JCUSvAf/ovA=="},
		// Twofish-192-OFB ANSI X.923 padding
		{clearText, aes192Key, iv, paddings.AnsiX923, "bqsQl68w2xLwV4RJNZAt+g=="},
		// Twofish-256-OFB ANSI X.923 padding
		{clearText, aes256Key, iv, paddings.AnsiX923, "rxORmBL5zdY4MAwyNHaTbg=="},
		// Twofish-128-OFB ISO/IEC 9797-1 padding
		{clearText, aes128Key, iv, paddings.ISO97971, "UpJQg/lduy/JCcSvAf/oug=="},
		// Twofish-192-OFB ISO/IEC 9797-1 padding
		{clearText, aes192Key, iv, paddings.ISO97971, "bqsQl68w2xLwVwRJNZAt/A=="},
		// Twofish-256-OFB ISO/IEC 9797-1 padding
		{clearText, aes256Key, iv, paddings.ISO97971, "rxORmBL5zdY4MIwyNHaTaA=="},
		// Twofish-128-OFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.PKCS7, "UpJQg/lduy/JCUKpB/nuvA=="},
		// Twofish-192-OFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.PKCS7, "bqsQl68w2xLwV4JPM5Yr+g=="},
		// Twofish-256-OFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.PKCS7, "rxORmBL5zdY4MAo0MnCVbg=="},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, base64.StdEncoding.EncodeToString(password))
		})
	}
}

func TestTwofishOFBDecrypt(t *testing.T) {
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
		// Twofish-128-OFB Zero padding
		{"UpJQg/lduy/JCUSvAf/oug==", aes128Key, iv, paddings.Zero, clearText},
		// Twofish-192-OFB Zero padding
		{"bqsQl68w2xLwV4RJNZAt/A==", aes192Key, iv, paddings.Zero, clearText},
		// Twofish-256-OFB Zero padding
		{"rxORmBL5zdY4MAwyNHaTaA==", aes256Key, iv, paddings.Zero, clearText},
		// Twofish-128-OFB ANSI X.923 padding
		{"UpJQg/lduy/JCUSvAf/ovA==", aes128Key, iv, paddings.AnsiX923, clearText},
		// Twofish-192-OFB ANSI X.923 padding
		{"bqsQl68w2xLwV4RJNZAt+g==", aes192Key, iv, paddings.AnsiX923, clearText},
		// Twofish-256-OFB ANSI X.923 padding
		{"rxORmBL5zdY4MAwyNHaTbg==", aes256Key, iv, paddings.AnsiX923, clearText},
		// Twofish-128-OFB ISO/IEC 9797-1 padding
		{"UpJQg/lduy/JCcSvAf/oug==", aes128Key, iv, paddings.ISO97971, clearText},
		// Twofish-192-OFB ISO/IEC 9797-1 padding
		{"bqsQl68w2xLwVwRJNZAt/A==", aes192Key, iv, paddings.ISO97971, clearText},
		// Twofish-256-OFB ISO/IEC 9797-1 padding
		{"rxORmBL5zdY4MIwyNHaTaA==", aes256Key, iv, paddings.ISO97971, clearText},
		// Twofish-128-OFB PKCS7 padding
		{"UpJQg/lduy/JCUKpB/nuvA==", aes128Key, iv, paddings.PKCS7, clearText},
		// Twofish-192-OFB PKCS7 padding
		{"bqsQl68w2xLwV4JPM5Yr+g==", aes192Key, iv, paddings.PKCS7, clearText},
		// Twofish-256-OFB PKCS7 padding
		{"rxORmBL5zdY4MAo0MnCVbg==", aes256Key, iv, paddings.PKCS7, clearText},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-OFB-%s", v.Mode), func(t *testing.T) {
			src, err := base64.StdEncoding.DecodeString(v.Encrypt)
			assert.NoError(t, err)
			password, err := TwofishOFBDecrypt(src, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, v.Expected, string(password))
		})
	}
}

func TestTwofishOFBISO10126(t *testing.T) {
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
		// Twofish-128-OFB PKCS7 padding
		{clearText, aes128Key, iv, paddings.ISO10126},
		// Twofish-192-OFB PKCS7 padding
		{clearText, aes192Key, iv, paddings.ISO10126},
		// Twofish-256-OFB PKCS7 padding
		{clearText, aes256Key, iv, paddings.ISO10126},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("Twofish-OFB-%s", v.Mode), func(t *testing.T) {
			password, err := TwofishOFBEncrypt(v.ClearText, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)

			ret, err := TwofishOFBDecrypt(password, v.Key, v.IV, v.Mode)
			assert.NoError(t, err)
			assert.Equal(t, clearText, ret)
		})
	}
}
