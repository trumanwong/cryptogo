package cryptogo

import (
	"crypto/des"
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
)

// TripleDesCBCEncrypt encrypts by 3des with cbc mode.
func TripleDesCBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// TripleDesCBCDecrypt decrypts by 3des with cbc mode.
func TripleDesCBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// TripleDesCFBEncrypt encrypts by 3des with cfb mode.
func TripleDesCFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// TripleDesCFBDecrypt decrypts by 3des with cfb mode.
func TripleDesCFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// TripleDesCTREncrypt encrypts by 3des with ctr mode.
func TripleDesCTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// TripleDesCTRDecrypt decrypts by 3des with ctr mode.
func TripleDesCTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// TripleDesECBEncrypt encrypts by 3des with ecb mode.
func TripleDesECBEncrypt(clearText, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBEncrypt(clearText, block, padding)
}

// TripleDesECBDecrypt decrypts by 3des with ecb mode.
func TripleDesECBDecrypt(src, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBDecrypt(src, block, padding)
}

// TripleDesOFBEncrypt encrypts by 3des with ofb mode.
func TripleDesOFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// TripleDesOFBDecrypt decrypts by 3des with ofb mode.
func TripleDesOFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}
