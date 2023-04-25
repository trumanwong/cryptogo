package cryptogo

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// SHA384 return sha384 encrypted string
func SHA384(clearText string) string {
	h := sha512.New384()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA384 returns a hexadecimal encoding of sha384 encrypted string
func HmacSHA384(key, clearText string) string {
	h := hmac.New(sha512.New384, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
