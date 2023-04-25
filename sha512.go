package cryptogo

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// SHA512 return sha512 encrypted string
func SHA512(clearText string) string {
	h := sha512.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA512 returns a hexadecimal encoding of sha512 encrypted string
func HmacSHA512(key, clearText string) string {
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
