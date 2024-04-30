package cryptogo

import "encoding/base32"

func Base32Encode(src []byte) []byte {
	dst := make([]byte, base32.StdEncoding.EncodedLen(len(src)))
	base32.StdEncoding.Encode(dst, src)
	return dst
}

func Base32Decode(src []byte) ([]byte, error) {
	dst := make([]byte, base32.StdEncoding.DecodedLen(len(src)))
	n, err := base32.StdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
