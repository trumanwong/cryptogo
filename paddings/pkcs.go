package paddings

import "bytes"

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
