package cryptogo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA224 SHA-224 is a variant of SHA-2 that produces a 224-bit digest.
func SHA224(clearText string) string {
	h := sha256.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA224 returns a hexadecimal encoding of sha-224 encrypted string
func HmacSHA224(key, clearText string) string {
	h := hmac.New(sha256.New224, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
