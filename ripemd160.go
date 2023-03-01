package cryptogo

import (
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func RIPEMD160(clearText string) string {
	h := ripemd160.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
