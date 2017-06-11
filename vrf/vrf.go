package vrf

import (
	"io"
	"bytes"

	"golang.org/x/crypto/ed25519"
	"github.com/yahoo/coname/vrf/vrf_ed25519"
)

const (
	PublicKeySize    = 32
	SecretKeySize    = 64
	Size             = 32
)

func GenerateKey(rnd io.Reader) (pk []byte, sk *[SecretKeySize]byte, err error) {
	pk, sks, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	sk = new([SecretKeySize]byte)
	copy(sk[:], sks)
	return
}


// Prove returns the vrf value and a proof such that Verify(pk, m, vrf, proof)
// == true. The vrf value is the same as returned by Compute(m, sk).
func Prove(m []byte, sk *[SecretKeySize]byte) (vrf, proof []byte) {
	var pk [PublicKeySize]byte
	copy(pk[:], sk[PublicKeySize:])
	pi, err := vrf_ed25519.ECVRF_prove(pk[:], sk[:], m)
	if err != nil {
		return nil, nil
	}
	return vrf_ed25519.ECVRF_proof2hash(pi), pi
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
func Verify(pkBytes, m, vrfBytes, proof []byte) bool {
	if !bytes.Equal(vrf_ed25519.ECVRF_proof2hash(proof), vrfBytes) {
		return false
	}
	res, _ := vrf_ed25519.ECVRF_verify(pkBytes, proof, m)
	return res
}

func Compute(m []byte, sk *[SecretKeySize]byte) []byte {
	vrf, _ := Prove(m, sk)
	return vrf
}
