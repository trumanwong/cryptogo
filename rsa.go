package cryptogo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type keyFormat string

const (
	PKCS1 keyFormat = "pkcs1"
	PKCS8 keyFormat = "pkcs8"
)

// RSAGenerateKeyPair Generate rsa key pair
func RSAGenerateKeyPair(bits int, format keyFormat) (privateKey, publicKey []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	var privateKeyBytes []byte
	switch format {
	case PKCS1:
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(key)
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		})
	case PKCS8:
		privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, errors.New(fmt.Sprintf("generate pkcs8 private key fail, %s", err))
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, nil, errors.New(fmt.Sprintf("generate public key fail, %s", err))
		}
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})
	default:
		return nil, nil, errors.New("invalid key format")
	}
	return
}

// parse public key
func parsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	var rsaPublicKey *rsa.PublicKey
	var err error
	// x509 parse
	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPublicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		rsaPublicKey, ok = pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is invalid public key")
		}
	default:
		return nil, errors.New("key is invalid format")
	}
	return rsaPublicKey, nil
}

// parse private key
func parsePrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	var rsaPrivateKey *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		rsaPrivateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is invalid private key")
		}
	default:
		return nil, errors.New("key is invalid private key")
	}
	return rsaPrivateKey, nil
}

// RSAEncrypt RSA Encrypt
func RSAEncrypt(src, publicKey []byte) (dst []byte, err error) {
	rsaPublicKey, err := parsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, src)
}

func RSADecrypt(src, privateKey []byte) ([]byte, error) {
	rsaPrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, src)
}

// RSASign rsa sign
func RSASign(src []byte, privateKey []byte, hash crypto.Hash) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	rsaPrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, hash, h.Sum(nil))
}

// RSAVerify rsa verify
func RSAVerify(src, sign, publicKey []byte, hash crypto.Hash) error {
	rsaPublicKey, err := parsePublicKey(publicKey)
	if err != nil {
		return err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(rsaPublicKey, hash, h.Sum(nil), sign)
}
