package mode

import (
	"crypto/cipher"
	"errors"
	"github.com/trumanwong/cryptogo/paddings"
)

// CBCEncrypt CBC encryption with block, iv and padding
func CBCEncrypt(clearText, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypt, clearText)
	return encrypt, nil
}

// CBCDecrypt CBC decryption with block, iv and padding
func CBCDecrypt(src, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesCBCDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypt, src)
	return paddings.UnPadding(decrypt, padding), nil
}
