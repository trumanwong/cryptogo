package cryptogo

import (
	"crypto/sha256"
	"fmt"
)

func SHA224(clearText string) string {
	h := sha256.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
