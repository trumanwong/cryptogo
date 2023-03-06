package cryptogo

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
)

func SHA3224(clearText string) string {
	h := sha3.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3256(clearText string) string {
	h := sha3.New256()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3384(clearText string) string {
	h := sha3.New384()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3512(clearText string) string {
	h := sha3.New512()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HmacSHA3224(key, clearText string) string {
	h := hmac.New(sha3.New224, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacSHA3256(key, clearText string) string {
	h := hmac.New(sha3.New256, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacSHA3384(key, clearText string) string {
	h := hmac.New(sha3.New384, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacSHA3512(key, clearText string) string {
	h := hmac.New(sha3.New512, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
