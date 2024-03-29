package paddings

import "bytes"

// ZeroPadding
func zeroPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	return append(src, padText...)
}

// ZeroUnPadding
func zeroUnPadding(src []byte) []byte {
	return bytes.TrimRight(src, string([]byte{0}))
}
