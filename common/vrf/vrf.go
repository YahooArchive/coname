// Package vrf implements a MOCK verifiable random function using SHA256.  It
// is still sound (bijective under computational assumptions), but it does not
// provide good randomness properties.
// See issue #5 for status of the actual proposal.
package vrf

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
)

const (
	PublicKeySize    = 0
	SecretKeySize    = 0
	Size             = 32
	intermediateSize = 0
	ProofSize        = 0
)

// GenerateKey creates a MOCK public/private key pair. rnd is used for
// randomness. If it is nil, `crypto/rand` is used.
func GenerateKey(rnd io.Reader) (pk []byte, sk *[SecretKeySize]byte, err error) {
	return nil, nil, nil
}

// Compute returns the value of a MOCK veirifiable random function of m.
func Compute(m []byte, sk *[SecretKeySize]byte) []byte {
	h := sha256.Sum256(m)
	return h[:]
}

// Prove returns a proof that will pass Verify, len(proof)=ProofSize.
func Prove(m []byte, sk *[SecretKeySize]byte) []byte {
	return nil
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
func Verify(pk, m, vrf, proof []byte) bool {
	h := sha256.Sum256(m)
	return subtle.ConstantTimeCompare(h[:], vrf) == 1
}
