package cryptogo

import (
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
	"golang.org/x/crypto/twofish"
)

// TwofishCBCEncrypt Twofish CBC encryption with key, iv and padding
func TwofishCBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// TwofishCBCDecrypt Twofish CBC decryption with key, iv and padding
func TwofishCBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// TwofishCFBEncrypt Twofish CFB encryption with key, iv and padding
func TwofishCFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// TwofishCFBDecrypt Twofish CFB decryption with key, iv and padding
func TwofishCFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// TwofishCTREncrypt Twofish CTR encryption with key, iv and padding
func TwofishCTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// TwofishCTRDecrypt Twofish CTR decryption with key, iv and padding
func TwofishCTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// TwofishECBEncrypt Twofish ECB encryption with key and padding
func TwofishECBEncrypt(clearText, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBEncrypt(clearText, block, padding)
}

// TwofishECBDecrypt Twofish ECB decryption with key and padding
func TwofishECBDecrypt(src, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBDecrypt(src, block, padding)
}

// TwofishOFBEncrypt Twofish OFB encryption with key, iv and padding
func TwofishOFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// TwofishOFBDecrypt Twofish OFB decryption with key, iv and padding
func TwofishOFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}
