package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// CBCEncrypt AES CBC encryption with secret key, iv and padding
func CBCEncrypt(clearText, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText, err = paddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypt, clearText)
	return encrypt, nil
}

// CBCDecrypt AES CBC decryption with secret key, iv and padding
func CBCDecrypt(src, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesCBCDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypt, src)
	return unPadding(decrypt, padding), nil
}
