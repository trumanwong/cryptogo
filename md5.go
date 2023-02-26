package cryptogo

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// MD5 return md5 encrypted string
func MD5(clearText string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(clearText)))
}

// MD5ToUpper Return MD5 uppercase encrypted string
func MD5ToUpper(clearText string) string {
	return strings.ToUpper(MD5(clearText))
}

// MD5ToLower Return MD5 lowercase encrypted string
func MD5ToLower(clearText string) string {
	return MD5(clearText)
}

// MD5Sixteen Returns a 16-bit MD5 encrypted string
func MD5Sixteen(clearText string) string {
	return MD5(clearText)[8:24]
}

// MD5SixteenToUpper Returns a 16-digit uppercase MD5 encrypted string
func MD5SixteenToUpper(clearText string) string {
	return strings.ToUpper(MD5Sixteen(clearText))
}

// MD5SixteenToLower Returns a 16-digit uppercase MD5 encrypted string
func MD5SixteenToLower(clearText string) string {
	return MD5Sixteen(clearText)
}
