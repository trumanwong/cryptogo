package cryptogo

import (
	"fmt"
	"golang.org/x/crypto/sha3"
)

func SHA3224(clearText string) string {
	h := sha3.New224()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3256(clearText string) string {
	h := sha3.New256()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3384(clearText string) string {
	h := sha3.New384()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA3512(clearText string) string {
	h := sha3.New512()
	h.Write([]byte(clearText))
	return fmt.Sprintf("%x", h.Sum(nil))
}
