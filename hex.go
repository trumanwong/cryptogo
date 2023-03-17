package cryptogo

import "encoding/hex"

// HexEncode hex encode
func HexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	n := hex.Encode(dst, src)
	return dst[:n]
}

// HexDecode hex decode
func HexDecode(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
