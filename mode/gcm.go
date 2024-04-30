package mode

import (
	"crypto/cipher"
	"github.com/trumanwong/cryptogo/paddings"
)

// GCMEncrypt GCM encryption with block, iv and padding
// return encrypt, nonce, error
func GCMEncrypt(clearText, nonce []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypt := aesgcm.Seal(nil, nonce, clearText, nil)
	return encrypt, nil
}

// GCMDecrypt GCM decryption with block, nonce and padding
func GCMDecrypt(src, nonce []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decrypt, err := aesgcm.Open(nil, nonce, src, nil)
	if err != nil {
		return nil, err
	}
	return paddings.UnPadding(decrypt, padding), nil
}
