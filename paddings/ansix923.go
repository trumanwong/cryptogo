package paddings

import "bytes"

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
