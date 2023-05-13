package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestSignVerify(t *testing.T) {
	src := []byte("trumanwong")

	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}

	rb, sb, err := Sign(prv, src, sha512.New())
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(&prv.PublicKey, src, rb, sb, sha512.New()) {
		t.Fatal("ecc: verify failed")
	}
}
