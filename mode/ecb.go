package mode

import (
	"crypto/cipher"
	"github.com/trumanwong/cryptogo/paddings"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

type ecbDecAble interface {
	NewECBDecrypter(iv []byte) cipher.BlockMode
}

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// ECBEncrypt ECB encryption with block and padding
func ECBEncrypt(clearText []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	clearText, err := paddings.PaddingClearText(clearText, padding, block.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypt := make([]byte, len(clearText))
	NewECBEncrypter(block).CryptBlocks(encrypt, clearText)
	return encrypt, nil
}

// ECBDecrypt ECB encryption with block and padding
func ECBDecrypt(src []byte, block cipher.Block, padding paddings.CipherPadding) ([]byte, error) {
	decrypt := make([]byte, len(src))
	NewECBDecrypter(block).CryptBlocks(decrypt, src)
	return paddings.UnPadding(decrypt, padding), nil
}
