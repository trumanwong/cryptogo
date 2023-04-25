package cryptogo

import (
	"crypto/des"
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
)

// DesCBCEncrypt encrypts by des with cbc mode.
func DesCBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// DesCBCDecrypt decrypts by des with cbc mode.
func DesCBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// DesCFBEncrypt encrypts by des with cfb mode.
func DesCFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// DesCFBDecrypt decrypts by des with cfb mode.
func DesCFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// DesCTREncrypt encrypts by des with ctr mode.
func DesCTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// DesCTRDecrypt decrypts by des with ctr mode.
func DesCTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// DesECBEncrypt encrypts by des with ecb mode.
func DesECBEncrypt(clearText, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBEncrypt(clearText, block, padding)
}

// DesECBDecrypt decrypts by des with ecb mode.
func DesECBDecrypt(src, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBDecrypt(src, block, padding)
}

// DesOFBEncrypt encrypts by des with ofb mode.
func DesOFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// DesOFBDecrypt decrypts by des with ofb mode.
func DesOFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}
