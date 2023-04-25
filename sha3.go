package cryptogo

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
)

// SHA3224 SHA3-224 is a variant of SHA3 that produces a 224-bit digest.
func SHA3224(clearText string) string {
	h := sha3.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SHA3256 SHA3-256 is a variant of SHA3 that produces a 256-bit digest.
func SHA3256(clearText string) string {
	h := sha3.New256()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SHA3384 SHA3-384 is a variant of SHA3 that produces a 384-bit digest.
func SHA3384(clearText string) string {
	h := sha3.New384()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SHA3512 SHA3-512 is a variant of SHA3 that produces a 512-bit digest.
func SHA3512(clearText string) string {
	h := sha3.New512()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HmacSHA3224  returns a hexadecimal encoding of sha3-224 encrypted string
func HmacSHA3224(key, clearText string) string {
	h := hmac.New(sha3.New224, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

// HmacSHA3256 returns a hexadecimal encoding of sha3-256 encrypted string
func HmacSHA3256(key, clearText string) string {
	h := hmac.New(sha3.New256, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

// HmacSHA3384 returns a hexadecimal encoding of sha3-384 encrypted string
func HmacSHA3384(key, clearText string) string {
	h := hmac.New(sha3.New384, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}

// HmacSHA3512 returns a hexadecimal encoding of sha3-512 encrypted string
func HmacSHA3512(key, clearText string) string {
	h := hmac.New(sha3.New512, []byte(key))
	h.Write([]byte(clearText))
	return hex.EncodeToString(h.Sum(nil))
}
