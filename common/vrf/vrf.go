// Package vrf implements a verifiable random function using SHA384,
// SHA512-384, P-384 and the Icart function.
package vrf

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/yahoo/coname/ed25519"
	"github.com/yahoo/coname/ed25519/edwards25519"
	"github.com/yahoo/coname/ed25519/extra25519"
)

const (
	PublicKeySize    = ed25519.PublicKeySize
	SecretKeySize    = ed25519.PrivateKeySize
	Size             = 32
	intermediateSize = ed25519.PublicKeySize
	ProofSize        = SecretKeySize + 32 + intermediateSize
)

// note on hashing: the use of sha512 matches the ed25519 signature scheme. In
// principle, HMAC-SHA512 may be a better fit.

// GenerateKey creates a public/private key pair. rnd is used for randomness.
// If it is nil, `crypto/rand` is used.
func GenerateKey(rnd io.Reader) (pk []byte, sk *[SecretKeySize]byte, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	pkA, sk, err := ed25519.GenerateKey(rnd)
	return pkA[:], sk, err
}

func expandSecret(sk *[SecretKeySize]byte) (x, skhr [32]byte) {
	skh := sha512.Sum512(sk[:32])
	copy(x[:], skh[:])
	copy(skhr[:], skh[32:])
	x[0] &= 248
	x[31] &= 127
	x[31] |= 64
	return
}

func Compute(m []byte, sk *[SecretKeySize]byte) []byte {
	x, _ := expandSecret(sk)
	var ii edwards25519.ExtendedGroupElement
	var iiB [32]byte
	edwards25519.GeScalarMult(&ii, &x, hashToCurve(m))
	ii.ToBytes(&iiB)

	vrf := sha512.New()
	vrf.Write(iiB[:]) // const length: Size
	vrf.Write(m)
	return vrf.Sum(nil)[:32]
}

func hashToCurve(m []byte) *edwards25519.ExtendedGroupElement {
	// H(n) = (f(h(n))^8)
	hmbH := sha512.Sum512(m)
	var hmb [32]byte
	copy(hmb[:], hmbH[:])
	var hm edwards25519.ExtendedGroupElement
	extra25519.HashToEdwards(&hm, &hmb)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	return &hm
}

// Prove returns a proof that will pass Verify, len(proof)=ProofSize.
func Prove(m []byte, sk *[SecretKeySize]byte) []byte {
	x, skhr := expandSecret(sk)
	var cH, rH [64]byte
	var r, c, minusC, t, grB, hrB, iiB [32]byte
	var ii, gr, hr edwards25519.ExtendedGroupElement

	hm := hashToCurve(m)
	edwards25519.GeScalarMult(&ii, &x, hm)
	ii.ToBytes(&iiB)

	hash := sha512.New()
	hash.Write(skhr[:])
	hash.Write(sk[32:]) // public key, as in ed25519
	hash.Write(m)
	hash.Sum(rH[:0])
	hash.Reset()
	edwards25519.ScReduce(&r, &rH)

	edwards25519.GeScalarMultBase(&gr, &r)
	edwards25519.GeScalarMult(&hr, &r, hm)
	gr.ToBytes(&grB)
	hr.ToBytes(&hrB)

	hash.Write(grB[:])
	hash.Write(hrB[:])
	hash.Write(m)
	hash.Sum(cH[:0])
	edwards25519.ScReduce(&c, &cH)

	edwards25519.ScNeg(&minusC, &c)
	edwards25519.ScMulAdd(&t, &x, &minusC, &r)

	var ret [ProofSize]byte
	copy(ret[:32], c[:])
	copy(ret[32:64], t[:])
	copy(ret[64:96], iiB[:])
	return ret[:]
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
func Verify(pkBytes, m, vrfBytes, proof []byte) bool {
	if len(proof) != ProofSize || len(vrfBytes) != Size || len(pkBytes) != PublicKeySize {
		return false
	}
	var pk, c, cRef, t, vrf, iiB, ABytes, BBytes [32]byte
	copy(vrf[:], vrfBytes)
	copy(pk[:], pkBytes)
	copy(c[:32], proof[:32])
	copy(t[:32], proof[32:64])
	copy(iiB[:], proof[64:96])

	h := sha512.New()
	h.Write(iiB[:]) // const length
	h.Write(m)
	if !bytes.Equal(h.Sum(nil)[:32], vrf[:32]) {
		return false
	}
	h.Reset()

	var P, B, ii, iic edwards25519.ExtendedGroupElement
	var A, hmtP, iicP edwards25519.ProjectiveGroupElement
	P.FromBytesBaseGroup(&pk)
	ii.FromBytesBaseGroup(&iiB)
	edwards25519.GeDoubleScalarMultVartime(&A, &c, &P, &t)
	A.ToBytes(&ABytes)

	hm := hashToCurve(m)
	edwards25519.GeDoubleScalarMultVartime(&hmtP, &t, hm, &[32]byte{})
	edwards25519.GeDoubleScalarMultVartime(&iicP, &c, &ii, &[32]byte{})
	iicP.ToExtended(&iic)
	hmtP.ToExtended(&B)
	edwards25519.GeAdd(&B, &B, &iic)
	B.ToBytes(&BBytes)

	var cH [64]byte
	h.Write(ABytes[:]) // const length
	h.Write(BBytes[:]) // const length
	h.Write(m)
	h.Sum(cH[:0])
	edwards25519.ScReduce(&cRef, &cH)
	return cRef == c
}
