package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"hash"
	"math/big"
)

// Sign signs the given hash (which should be the result of hashing a larger message)
func Sign(p *PrivateKey, src []byte, h hash.Hash) ([]byte, []byte, error) {
	h.Write(src)
	r, s, err := ecdsa.Sign(rand.Reader, p.ExportECDSA(), h.Sum(nil))
	if err != nil {
		return nil, nil, err
	}
	rb, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sb, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rb, sb, nil
}

func Verify(p *PublicKey, src []byte, rb, sb []byte, h hash.Hash) bool {
	var r, s big.Int
	if err := r.UnmarshalText(rb); err != nil {
		return false
	}
	if err := s.UnmarshalText(sb); err != nil {
		return false
	}
	h.Write(src)
	return ecdsa.Verify(p.ExportECDSA(), h.Sum(nil), &r, &s)
}
