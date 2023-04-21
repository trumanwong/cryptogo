package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// CFBEncrypt AES CFB encryption with secret key, iv and padding
func CFBEncrypt(clearText, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText, err = paddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encrypt, clearText)
	return encrypt, nil
}

// CFBDecrypt AES CFB decryption with secret key, iv and padding
func CFBDecrypt(src, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesCFBDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(decrypt, src)
	return unPadding(decrypt, padding), nil
}
