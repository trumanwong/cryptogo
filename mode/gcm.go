package mode

import (
	"crypto/cipher"
	"crypto/rand"
	"github.com/trumanwong/cryptogo/paddings"
	"io"
)

// GCMEncrypt GCM encryption with block and padding
// return encrypt, nonce, error
func GCMEncrypt(clearText []byte, block cipher.Block) ([]byte, []byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, paddings.No, block.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	encrypt := aesgcm.Seal(nil, nonce, clearText, nil)
	return encrypt, nonce, nil
}

// GCMDecrypt GCM decryption with block, iv and padding
func GCMDecrypt(src, nonce []byte, block cipher.Block) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decrypt, err := aesgcm.Open(nil, nonce, src, nil)

	return decrypt, err
}
