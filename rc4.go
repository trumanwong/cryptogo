package cryptogo

import (
	"crypto/rc4"
)

// RC4Encrypt RC4 encryption.
// key: RC4 key
// clearText: plaintext password
func RC4Encrypt(key, clearText string) ([]byte, error) {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(clearText))
	cipher.XORKeyStream(dst, []byte(clearText))
	return HexEncode(dst), nil
}

func RC4Decrypt(key, password string) ([]byte, error) {
	decode, err := HexDecode([]byte(password))
	if err != nil {
		return nil, err
	}
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(decode))
	cipher.XORKeyStream(dst, decode)
	return dst, nil
}
