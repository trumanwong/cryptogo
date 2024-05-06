package cryptogo

import (
	"fmt"
	"log"
	"testing"
)

func TestJwtEncrypt(t *testing.T) {
	key := []byte("key")
	claims := map[string]interface{}{
		"username": "trumanwong",
		"password": "123",
	}
	tokenString, err := JwtEncrypt(key, claims)
	if err != nil {
		t.Error(err)
	}
	t.Log(tokenString)
}

func ExampleJwtEncrypt() {
	key := []byte("key")
	claims := map[string]interface{}{
		"username": "trumanwong",
		"password": "123",
	}
	tokenString, err := JwtEncrypt(key, claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tokenString)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6IjEyMyIsInVzZXJuYW1lIjoidHJ1bWFud29uZyJ9.Mr6i2H2GaXyKFAuoqJ3JA67wSpHP6iBucIQnuofqCCQ
}

func TestJwtDecrypt(t *testing.T) {
	key := []byte("key")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6IjEyMyIsInVzZXJuYW1lIjoidHJ1bWFud29uZyJ9.Mr6i2H2GaXyKFAuoqJ3JA67wSpHP6iBucIQnuofqCCQ"
	claims, err := JwtDecrypt(tokenString, key)
	if err != nil {
		t.Error(err)
	}
	t.Log(claims)
}

func ExampleJwtDecrypt() {
	key := []byte("key")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6IjEyMyIsInVzZXJuYW1lIjoidHJ1bWFud29uZyJ9.Mr6i2H2GaXyKFAuoqJ3JA67wSpHP6iBucIQnuofqCCQ"
	claims, err := JwtDecrypt(tokenString, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims["username"])
	// Output: trumanwong
}
