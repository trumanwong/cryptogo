package paddings

import "bytes"

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
