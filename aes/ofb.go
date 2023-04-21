package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// OFBEncrypt AES OFB encryption with secret key, iv and padding
func OFBEncrypt(clearText, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText, err = paddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewOFB(block, iv).XORKeyStream(encrypt, clearText)
	return encrypt, nil
}

// OFBDecrypt AES OFB decryption with secret key, iv and padding
func OFBDecrypt(src, key, iv []byte, padding cipherPadding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesOFBDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(decrypt, src)
	return unPadding(decrypt, padding), nil
}
