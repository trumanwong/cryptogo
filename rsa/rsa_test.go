package rsa

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func Example() {
	priKey, pubKey, err := GenerateKeyPair(2048, PKCS8)
	if err != nil {
		log.Fatal(err)
	}

	src := []byte("trumanwong")
	dst, err := Encrypt(src, pubKey)
	if err != nil {
		log.Fatal(err)
	}

	dst, err = Decrypt(dst, priKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(dst))
	// Output: trumanwong
}

func TestEncrypt(t *testing.T) {
	priKey, pubKey, err := GenerateKeyPair(2048, PKCS1)
	if err != nil {
		assert.NoError(t, err)
	}
	t.Logf("public key: %s\n", pubKey)
	t.Logf("private key: %s\n", priKey)

	src := []byte("trumanwong")
	dst, err := Encrypt(src, pubKey)
	assert.NoError(t, err)
	t.Logf("encrypt out: %s\n", base64.RawStdEncoding.EncodeToString(dst))

	dst, err = Decrypt(dst, priKey)
	assert.NoError(t, err)

	assert.Equal(t, src, dst)
}

func ExampleSign() {
	priKey, pubKey, err := GenerateKeyPair(2048, PKCS8)
	if err != nil {
		log.Fatal(err)
	}

	src := []byte("trumanwong")
	sign, err := Sign(src, priKey, crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	err = Verify(src, sign, pubKey, crypto.SHA256)
	fmt.Println(err)
	// Output: <nil>
}

func TestSign(t *testing.T) {
	priKey, pubKey, err := GenerateKeyPair(2048, PKCS1)
	if err != nil {
		assert.NoError(t, err)
	}
	t.Logf("public key: %s\n", pubKey)
	t.Logf("private key: %s\n", priKey)

	src := []byte("trumanwong")
	sign, err := Sign(src, priKey, crypto.SHA256)
	assert.NoError(t, err)
	t.Logf("sign out: %s\n", base64.RawStdEncoding.EncodeToString(sign))

	err = Verify(src, sign, pubKey, crypto.SHA256)
	assert.NoError(t, err)
}
