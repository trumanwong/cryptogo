package cryptogo

import (
	"crypto/sha512"
	"fmt"
)

func SHA512(clearText string) string {
	h := sha512.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
