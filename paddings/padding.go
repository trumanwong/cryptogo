package paddings

import (
	"fmt"
)

type CipherPadding string

const (
	No       CipherPadding = "No"
	Zero     CipherPadding = "ZERO"
	AnsiX923 CipherPadding = "ANSI X.923"
	ISO97971 CipherPadding = "ISO/IEC 9797-1"
	ISO10126 CipherPadding = "ISO 10126"
	PKCS5    CipherPadding = "PKCS5"
	PKCS7    CipherPadding = "PKCS7"
)

// PaddingClearText padding clearText with padding mode.
func PaddingClearText(clearText []byte, padding CipherPadding, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("padding.%s ClearText blockSize is out of bounds: %d", padding, blockSize)
	}
	switch padding {
	case Zero:
		return zeroPadding(clearText, blockSize), nil
	case AnsiX923:
		return ansiX923Padding(clearText, blockSize), nil
	case ISO97971:
		return iso97971Padding(clearText, blockSize), nil
	case ISO10126:
		return iso10126Padding(clearText, blockSize)
	case PKCS5:
		return pkcs5Padding(clearText), nil
	case PKCS7:
		return pkcs7Padding(clearText, blockSize), nil
	}
	return clearText, nil
}

// UnPadding unpadding src with padding mode.
func UnPadding(src []byte, padding CipherPadding) []byte {
	switch padding {
	case Zero:
		return zeroUnPadding(src)
	case AnsiX923:
		return ansiX923UnPadding(src)
	case ISO97971:
		return iso97971UnPadding(src)
	case ISO10126:
		return iso10126UnPadding(src)
	case PKCS5:
		return pkcs5UnPadding(src)
	case PKCS7:
		return pkcs7UnPadding(src)
	}
	return src
}
