package cryptogo

import (
	"crypto/aes"
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
)

// AesCBCEncrypt Aes CBC encryption with key, iv and padding
func AesCBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// AesCBCDecrypt Aes CBC decryption with key, iv and padding
func AesCBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// AesCFBEncrypt Aes CFB encryption with key, iv and padding
func AesCFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// AesCFBDecrypt Aes CFB decryption with key, iv and padding
func AesCFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// AesCTREncrypt Aes CTR encryption with key, iv and padding
func AesCTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// AesCTRDecrypt Aes CTR decryption with key, iv and padding
func AesCTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// AesECBEncrypt Aes ECB encryption with key, iv and padding
func AesECBEncrypt(clearText, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBEncrypt(clearText, block, padding)
}

// AesECBDecrypt Aes ECB decryption with key, iv and padding
func AesECBDecrypt(src, key []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.ECBDecrypt(src, block, padding)
}

// AesOFBEncrypt Aes OFB encryption with key, iv and padding
func AesOFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// AesOFBDecrypt Aes OFB decryption with key, iv and padding
func AesOFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}

// AesGCMEncrypt Aes GCM encryption with key
func AesGCMEncrypt(clearText, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	return mode.GCMEncrypt(clearText, block)
}

func AesGCMDecrypt(src, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.GCMDecrypt(src, nonce, block)
}
