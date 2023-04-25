package paddings

import "bytes"

// ANSI X.923 padding is identical to ISO 10126 padding, except that the padding bytes are not random, but are always zeros.
func ansiX923Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	paddingSlice := append(bytes.Repeat([]byte{byte(0)}, padding-1), byte(padding))
	return append(src, paddingSlice...)
}

// ANSI X.923 unpadding is identical to ISO 10126 unpadding.
func ansiX923UnPadding(src []byte) []byte {
	if len(src) == 0 {
		return []byte("")
	}
	n := len(src) - int(src[len(src)-1])
	return src[0:n]
}
