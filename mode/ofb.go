package mode

import (
	"crypto/cipher"
	"errors"
	"github.com/trumanwong/cryptogo/paddings"
)

// OFBEncrypt OFB encryption with block, iv and padding
func OFBEncrypt(clearText, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewOFB(block, iv).XORKeyStream(encrypt, clearText)
	return encrypt, nil
}

// OFBDecrypt OFB decryption with block, iv and padding
func OFBDecrypt(src, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesOFBDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(decrypt, src)
	return paddings.UnPadding(decrypt, padding), nil
}
