package mode

import (
	"crypto/cipher"
	"errors"
	"github.com/trumanwong/cryptogo/paddings"
)

// CFBEncrypt CFB encryption with block, iv and padding
func CFBEncrypt(clearText, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encrypt, clearText)
	return encrypt, nil
}

// CFBDecrypt CFB decryption with block, iv and padding
func CFBDecrypt(src, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesCFBDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(decrypt, src)
	return paddings.UnPadding(decrypt, padding), nil
}
