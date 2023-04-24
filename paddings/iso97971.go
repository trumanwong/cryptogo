package paddings

// ISO/IEC 9797-1 Padding Method
func iso97971Padding(src []byte, blockSize int) []byte {
	return zeroPadding(append(src, 0x80), blockSize)
}

func iso97971UnPadding(dst []byte) []byte {
	data := zeroUnPadding(dst)
	return data[:len(data)-1]
}
