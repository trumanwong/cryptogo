package cryptogo

import (
	"crypto/cipher"
	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
	"github.com/trumanwong/cryptogo/mode"
	"github.com/trumanwong/cryptogo/paddings"
)

// Sm4CBCEncrypt Sm4 CBC encryption with key, iv and padding
func Sm4CBCEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCEncrypt(clearText, iv, block, padding)
}

// Sm4CBCDecrypt Sm4 CBC decryption with key, iv and padding
func Sm4CBCDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CBCDecrypt(src, iv, block, padding)
}

// Sm4CFBEncrypt Sm4 CFB encryption with key, iv and padding
func Sm4CFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBEncrypt(clearText, iv, block, padding)
}

// Sm4CFBDecrypt Sm4 CFB decryption with key, iv and padding
func Sm4CFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CFBDecrypt(src, iv, block, padding)
}

// Sm4OFBEncrypt Sm4 OFB encryption with key, iv and padding
func Sm4OFBEncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBEncrypt(clearText, iv, block, padding)
}

// Sm4OFBDecrypt Sm4 OFB decryption with key, iv and padding
func Sm4OFBDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.OFBDecrypt(src, iv, block, padding)
}

// Sm4CTREncrypt Sm4 CTR encryption with key, iv and padding
func Sm4CTREncrypt(clearText, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTREncrypt(clearText, iv, block, padding)
}

// Sm4CTRDecrypt Sm4 CTR decryption with key, iv and padding
func Sm4CTRDecrypt(src, key, iv []byte, padding paddings.CipherPadding) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mode.CTRDecrypt(src, iv, block, padding)
}

// Sm4CCMEncrypt Sm4 CCM encryption with key, nonce and padding
func Sm4CCMEncrypt(clearText, key, nonce []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4ccm, err := smcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}
	return sm4ccm.Seal(nil, nonce, clearText, nil), nil
}

// Sm4CCMDecrypt Sm4 CCM decryption with key, nonce and padding
func Sm4CCMDecrypt(src, key, nonce []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4ccm, err := smcipher.NewCCM(block)
	if err != nil {
		return nil, err
	}
	return sm4ccm.Open(nil, nonce, src, nil)
}

func Sm4GCMEncrypt(clearText, key, nonce []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	return sm4gcm.Seal(nil, nonce, clearText, nil), nil
}

func Sm4GCMDecrypt(src, key, nonce []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return sm4gcm.Open(nil, nonce, src, nil)
}
