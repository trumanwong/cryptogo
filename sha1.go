package cryptogo

import (
	"crypto/sha1"
	"fmt"
)

func SHA1(clearText string) string {
	// start with a new hash
	h := sha1.New()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
