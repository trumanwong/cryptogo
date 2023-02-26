package cryptogo

import (
	"crypto/sha256"
	"fmt"
)

func SHA256(clearText string) string {
	h := sha256.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
