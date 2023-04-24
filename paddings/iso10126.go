package paddings

import "crypto/rand"

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
