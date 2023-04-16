package cryptogo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// block cipher mode of operation
type blockMode string

const (
	CBC blockMode = "cbc"
	ECB blockMode = "ecb"
	CFB blockMode = "cfb"
	OFB blockMode = "ofb"
	CTR blockMode = "ctr"
)

type cipherPadding string

const (
	No    cipherPadding = "no"
	Empty cipherPadding = "empty"
	Zero  cipherPadding = "zero"
	PKCS5 cipherPadding = "pkcs5"
	PKCS7 cipherPadding = "pkcs7"
)

func AesEncrypt(clearText, key, iv []byte, mode blockMode, padding cipherPadding) ([]byte, error) {
	if len(clearText) == 0 {
		return []byte(""), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := block.BlockSize()

	if mode != ECB && len(iv) != block.BlockSize() {
		return nil, errors.New("cryptogo.AesEncrypt: IV length must equal block size")
	}

	switch padding {
	case No:
	case Empty:
		clearText = emptyPadding(clearText, size)
	case Zero:
		clearText = zeroPadding(clearText, size)
	case PKCS5:
		clearText = pKCS5Padding(clearText)
	case PKCS7:
		clearText = pKCS7Padding(clearText, size)
	}

	switch mode {
	case ECB:
		return aesCBCEncrypt(clearText, key, iv, block)
	}
}

func AesDecrypt() {

}

func aesCBCEncrypt(clearText, key, iv []byte, block cipher.Block) ([]byte, error) {
	encrypt := make([]byte, len(clearText))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypt, clearText)
	return encrypt, nil
}

func aesCBCDecrypt(input, key, iv []byte, block cipher.Block) ([]byte, error) {
	decrypt := make([]byte, len(input))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypt, input)
	return decrypt, nil
}

func emptyPadding(clearText []byte, blockSize int) []byte {
	paddingSize := blockSize - len(clearText)%blockSize
	paddingText := bytes.Repeat([]byte(" "), paddingSize)
	return append(clearText, paddingText...)
}

func emptyUnPadding(src []byte) []byte {
	return bytes.TrimRight(src, " ")
}

// zero padding
// All the bytes that are required to be padded are padded with zero.
func zeroPadding(clearText []byte, blockSize int) []byte {
	padding := blockSize - len(clearText)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	return append(clearText, padText...)
}

func zeroUnPadding(src []byte) []byte {
	return bytes.TrimRight(src, string([]byte{0}))
}

// PKCS#5 padding is identical to PKCS#7 padding, except that it has only been defined for block ciphers that use a 64-bit (8-byte) block size.
func pKCS5Padding(clearText []byte) []byte {
	return pKCS7Padding(clearText, 8)
}

func pcKCS5UnPadding(src []byte) []byte {
	return pcKCS7UnPadding(src)
}

// PKCS#7 paddin
func pKCS7Padding(clearText []byte, blockSize int) []byte {
	padding := blockSize - len(clearText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(clearText, padText...)
}

func pcKCS7UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return []byte("")
	}
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
