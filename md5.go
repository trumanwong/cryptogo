package cryptogo

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// MD5 return md5 encrypted string
func MD5(clearText []byte) string {
	return fmt.Sprintf("%x", md5.Sum(clearText))
}

// MD5ToUpper Return MD5 uppercase encrypted string
func MD5ToUpper(clearText []byte) string {
	return strings.ToUpper(MD5(clearText))
}

// MD5ToLower Return MD5 lowercase encrypted string
func MD5ToLower(clearText []byte) string {
	return MD5(clearText)
}

// MD5Sixteen Returns a 16-bit MD5 encrypted string
func MD5Sixteen(clearText []byte) string {
	return MD5(clearText)[8:24]
}

// MD5SixteenToUpper Returns a 16-digit uppercase MD5 encrypted string
func MD5SixteenToUpper(clearText []byte) string {
	return strings.ToUpper(MD5Sixteen(clearText))
}

// MD5SixteenToLower Returns a 16-digit uppercase MD5 encrypted string
func MD5SixteenToLower(clearText []byte) string {
	return MD5Sixteen(clearText)
}

// HmacMD5 Keyed-hash message authentication codes (HMAC) is a mechanism for message authentication using cryptographic hash functions.
func HmacMD5(key, clearText []byte) string {
	h := hmac.New(md5.New, key)
	h.Write(clearText)
	return hex.EncodeToString(h.Sum(nil))
}
