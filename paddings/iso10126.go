package paddings

import "crypto/rand"

// ISO/IEC 10126 Padding Method
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

// ISO/IEC 10126 unpadding is identical to PKCS#7 unpadding.
func iso10126UnPadding(src []byte) []byte {
	return pkcs7UnPadding(src)
}
