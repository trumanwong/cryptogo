package cryptogo

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

// RIPEMD160 return ripemd160 encrypted string
func RIPEMD160(clearText string) string {
	h := ripemd160.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacRIPEMD160 returns a hexadecimal encoding of ripemd160 encrypted string
func HmacRIPEMD160(key, clearText string) string {
	h := hmac.New(ripemd160.New, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
