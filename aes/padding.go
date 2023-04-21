package aes

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

type cipherPadding string

const (
	Zero     cipherPadding = "ZERO"
	AnsiX923 cipherPadding = "ANSI X.923"
	ISO97971 cipherPadding = "ISO/IEC 9797-1"
	ISO10126 cipherPadding = "ISO 10126"
	PKCS5    cipherPadding = "PKCS5"
	PKCS7    cipherPadding = "PKCS7"
)

func paddingClearText(clearText []byte, padding cipherPadding, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("padding.%s ClearText blockSize is out of bounds: %d", padding, blockSize)
	}
	switch padding {
	case Zero:
		return zeroPadding(clearText, blockSize), nil
	case AnsiX923:
		return ansiX923Padding(clearText, blockSize), nil
	case ISO97971:
		return iso97971Padding(clearText, blockSize), nil
	case ISO10126:
		return iso10126Padding(clearText, blockSize)
	case PKCS5:
		return pkcs5Padding(clearText), nil
	case PKCS7:
		return pkcs7Padding(clearText, blockSize), nil
	}
	return clearText, nil
}

func unPadding(src []byte, padding cipherPadding) []byte {
	switch padding {
	case Zero:
		return zeroUnPadding(src)
	case AnsiX923:
		return ansiX923UnPadding(src)
	case ISO97971:
		return iso97971UnPadding(src)
	case ISO10126:
		return iso10126UnPadding(src)
	case PKCS5:
		return pkcs5UnPadding(src)
	case PKCS7:
		return pkcs7UnPadding(src)
	}
	return src
}

// zero padding
// All the bytes that are required to be padded are padded with zero.
func zeroPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	return append(src, padText...)
}

func zeroUnPadding(src []byte) []byte {
	return bytes.TrimRight(src, string([]byte{0}))
}

func ansiX923Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	paddingSlice := append(bytes.Repeat([]byte{byte(0)}, padding-1), byte(padding))
	return append(src, paddingSlice...)
}

func ansiX923UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return []byte("")
	}
	n := len(src) - int(src[len(src)-1])
	return src[0:n]
}

// ISO/IEC 9797-1 Padding Method
func iso97971Padding(src []byte, blockSize int) []byte {
	return zeroPadding(append(src, 0x80), blockSize)
}

func iso97971UnPadding(dst []byte) []byte {
	data := zeroUnPadding(dst)
	return data[:len(data)-1]
}

// implements ISO 10126 byte padding. This has been withdrawn in 2007.
func iso10126Padding(src []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(src)%blockSize
	r := make([]byte, padding-1)
	_, err := rand.Read(r)
	if err != nil {
		return nil, err
	}
	padText := append(r, byte(padding))
	return append(src, padText...), nil
}

func iso10126UnPadding(src []byte) []byte {
	return pkcs7UnPadding(src)
}

// PKCS#5 padding is identical to PKCS#7 padding, except that it has only been defined for block ciphers that use a 64-bit (8-byte) block size.
func pkcs5Padding(src []byte) []byte {
	return pkcs7Padding(src, 8)
}

func pkcs5UnPadding(src []byte) []byte {
	return pkcs7UnPadding(src)
}

func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func pkcs7UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	length := len(src)
	return src[:(length - int(src[length-1]))]
}
