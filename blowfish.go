package cryptogo

import (
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
	"golang.org/x/crypto/blowfish"
)

// BlowfishCBCEncrypt Blowfish CBC encryption with key, iv and padding
func BlowfishCBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// BlowfishCBCDecrypt Blowfish CBC decryption with key, iv and padding
func BlowfishCBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// BlowfishCFBEncrypt Blowfish CFB encryption with key, iv and padding
func BlowfishCFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// BlowfishCFBDecrypt Blowfish CFB decryption with key, iv and padding
func BlowfishCFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// BlowfishCTREncrypt Blowfish CTR encryption with key, iv and padding
func BlowfishCTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// BlowfishCTRDecrypt Blowfish CTR decryption with key, iv and padding
func BlowfishCTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// BlowfishECBEncrypt Blowfish ECB encryption with key and padding
func BlowfishECBEncrypt(clearText, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBEncrypt(clearText, block, padding)
}

// BlowfishECBDecrypt Blowfish ECB decryption with key and padding
func BlowfishECBDecrypt(src, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBDecrypt(src, block, padding)
}

// BlowfishOFBEncrypt Blowfish OFB encryption with key, iv and padding
func BlowfishOFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// BlowfishOFBDecrypt Blowfish OFB decryption with key, iv and padding
func BlowfishOFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}
