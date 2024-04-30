package cryptogo

import (
	"fmt"
	"github.com/emmansun/gmsm/sm3"
)

// Sm3 encrypts by sm3.
func Sm3(clearText []byte) string {
	h := sm3.New()
	h.Write(clearText)
	return fmt.Sprintf("%x", h.Sum(nil))
}
