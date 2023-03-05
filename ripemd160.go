package cryptogo

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func RIPEMD160(clearText string) string {
	h := ripemd160.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HmacRIPEMD160(key, clearText string) string {
	h := hmac.New(ripemd160.New, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
