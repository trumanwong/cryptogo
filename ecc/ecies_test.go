package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func Example() {
	src := []byte("trumanwong")

	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := Encrypt(rand.Reader, &prv.PublicKey, src, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := prv.Decrypt(ct, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(bytes.Equal(pt, src))
	// Output: true
}

func TestEncryptDecrypt(t *testing.T) {
	src := []byte("trumanwong")

	prv1, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		assert.NoError(t, err)
	}

	prv2, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		assert.NoError(t, err)
	}

	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, src, nil, nil)
	if err != nil {
		assert.NoError(t, err)
	}

	pt, err := prv2.Decrypt(ct, nil, nil)
	if err != nil {
		assert.NoError(t, err)
	}

	if !bytes.Equal(pt, src) {
		t.Fatal("ecies: plaintext doesn't match message")
	}

	_, err = prv1.Decrypt(ct, nil, nil)
	if err == nil {
		t.Fatal("ecies: encryption should not have succeeded")
	}
}
