package cryptogo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA256 return sha256 encrypted string
func SHA256(clearText string) string {
	h := sha256.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA256 returns a hexadecimal encoding of sha256 encrypted string
func HmacSHA256(key, clearText string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
