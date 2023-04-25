package cryptogo

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// SHA1 return sha1 encrypted string
func SHA1(clearText string) string {
	// start with a new hash
	h := sha1.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA1 returns a hexadecimal encoding of sha1 encrypted string
func HmacSHA1(key, clearText string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
