package cryptogo

import (
	"crypto/sha512"
	"fmt"
)

func SHA384(clearText string) string {
	h := sha512.New384()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
