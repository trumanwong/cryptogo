package paddings

import "bytes"

// PKCS#5 padding
func pkcs5Padding(src []byte) []byte {
	return pkcs7Padding(src, 8)
}

// PKCS#5 unpadding
func pkcs5UnPadding(src []byte) []byte {
	return pkcs7UnPadding(src)
}

// PKCS#7 padding
func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// PKCS#7 unpadding
func pkcs7UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	length := len(src)
	return src[:(length - int(src[length-1]))]
}
