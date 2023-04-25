package paddings

// ISO/IEC 9797-1 Padding Method 2
func iso97971Padding(src []byte, blockSize int) []byte {
	return zeroPadding(append(src, 0x80), blockSize)
}

// ISO/IEC 9797-1 unpadding is identical to Zero unpadding.
func iso97971UnPadding(dst []byte) []byte {
	data := zeroUnPadding(dst)
	return data[:len(data)-1]
}
