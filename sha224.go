package cryptogo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func SHA224(clearText string) string {
	h := sha256.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HmacSHA224(key, clearText string) string {
	h := hmac.New(sha256.New224, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
