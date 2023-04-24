package mode

import (
	"crypto/cipher"
	"errors"
	"github.com/trumanwong/cryptogo/paddings"
)

// CTREncrypt CTR encryption with block, iv and padding
func CTREncrypt(clearText, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	cipher.NewCTR(block, iv).XORKeyStream(encrypt, clearText)
	return encrypt, nil
}

// CTRDecrypt CTR decryption with block, iv and padding
func CTRDecrypt(src, iv []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		return nil, errors.New("AesCTRDecrypt: IV length must equal block size")
	}

	decrypt := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(decrypt, src)
	return paddings.UnPadding(decrypt, padding), nil
}
