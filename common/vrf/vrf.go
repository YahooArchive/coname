// Package vrf implements a verifiable random function using SHA384,
// SHA512-384, P-384 and the Icart function.
package vrf

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/yahoo/coname/common/icart"
)

const (
	PublicKeySize    = 1 + 48 + 48
	SecretKeySize    = 32 + PublicKeySize
	Size             = 32
	intermediateSize = PublicKeySize
	ProofSize        = 48 + 48 + intermediateSize
)

// GenerateKey creates a public/private key pair. rnd is used for randomness.
// If it is nil, `crypto/rand` is used.
func GenerateKey(rnd io.Reader) (pk []byte, sk *[SecretKeySize]byte, err error) {
	sk = new([SecretKeySize]byte)
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, sk[:32]); err != nil {
		return nil, nil, err
	}

	h := sha512.New()
	h.Write(sk[:32])
	ecsk := h.Sum(nil)[:48]

	x, y := elliptic.P384().ScalarBaseMult(ecsk)
	pk = elliptic.Marshal(elliptic.P384(), x, y)
	if len(pk) != PublicKeySize || copy(sk[32:], pk) != len(pk) {
		panic("vrf GenerateKey space accounting failed")
	}
	return pk, sk, err
}

// Compute returns the value of a veirifiable random function of m using key k.
// H(m, H'(m)^k). TODO: I think length extension does not matter because the
// value we are trying to hide is last, but maybe we should double up anyway?
func Compute(m []byte, sk *[SecretKeySize]byte) []byte {
	vrf := sha512.New()
	vrf.Write(compute(m, sk)) // const length
	vrf.Write(m)
	return vrf.Sum(nil)[:32]
}

func compute(m []byte, sk *[SecretKeySize]byte) []byte {
	h := sha512.New()
	h.Write(sk[:32])
	k := h.Sum(nil)[:48]

	mx, my := hashToCurve(m)
	mkx, mky := elliptic.P384().ScalarMult(mx, my, k)
	if !elliptic.P384().Params().IsOnCurve(mkx, mky) {
		panic("computed intermediate VRF is not on curve")
	}
	return elliptic.Marshal(elliptic.P384(), mkx, mky)
}

// Prove returns a proof that will pass Verify, len(proof)=ProofSize.
func Prove(m []byte, sk *[SecretKeySize]byte) []byte {
	h := sha512.New()
	h.Write(sk[:32])

	var hsk, hm, cH [sha512.Size]byte
	h.Sum(hsk[:0])
	k := hsk[:48]

	h.Reset()
	h.Write(hsk[32:])
	h.Write(m)
	h.Sum(hm[:0])
	r := hm[:48]

	grx, gry := elliptic.P384().ScalarBaseMult(r)
	hx, hy := hashToCurve(m)
	hrx, hry := elliptic.P384().ScalarMult(hx, hy, r)

	h.Reset()
	h.Write(m)
	h.Write(elliptic.Marshal(elliptic.P384(), grx, gry)) // const length
	h.Write(elliptic.Marshal(elliptic.P384(), hrx, hry)) // const length
	h.Sum(cH[:0])
	var t, c big.Int
	c.SetBytes(cH[:48]) // c
	c.Mul(&c, new(big.Int).SetBytes(k))
	c.Mod(&c, elliptic.P384().Params().N) // c*k
	t.SetBytes(r)
	t.Sub(&t, &c)
	t.Mod(&t, elliptic.P384().Params().N) // r - c*k
	return append(append(cH[:48], t.Bytes()...), compute(m, sk)...)
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
func Verify(pk, m, vrf, proof []byte) bool {
	if len(proof) != ProofSize || len(vrf) != Size || len(pk) != PublicKeySize {
		return false
	}
	c, t, vIntermediate := proof[:48], proof[48:96], proof[96:]
	h := sha512.New()
	h.Write(vIntermediate) // const length
	h.Write(m)
	if subtle.ConstantTimeCompare(h.Sum(nil)[:32], vrf) != 1 {
		return false
	}

	pkx, pky := elliptic.Unmarshal(elliptic.P384(), pk[:])
	_ = "breakpoint"
	vx, vy := elliptic.Unmarshal(elliptic.P384(), vIntermediate[:])
	if vx == nil {
		return false
	}
	// some of these checks may be redundant. When one is proven redundant, it
	// should be removed.
	if pkx.Cmp(elliptic.P384().Params().P) >= 0 {
		return false
	}
	if pky.Cmp(elliptic.P384().Params().P) >= 0 {
		return false
	}
	if !elliptic.P384().Params().IsOnCurve(pkx, pky) {
		return false
	}
	if vx.Cmp(elliptic.P384().Params().P) >= 0 {
		return false
	}
	if vy.Cmp(elliptic.P384().Params().P) >= 0 {
		return false
	}
	if !elliptic.P384().Params().IsOnCurve(vx, vy) {
		return false
	}
	Gcx, Gcy := elliptic.P384().ScalarMult(pkx, pky, c)
	gtx, gty := elliptic.P384().ScalarBaseMult(t)
	grx, gry := elliptic.P384().Add(gtx, gty, Gcx, Gcy)
	mx, my := hashToCurve(m)
	mtx, mty := elliptic.P384().ScalarMult(mx, my, t)
	vcx, vcy := elliptic.P384().ScalarMult(vx, vy, c)
	hrx, hry := elliptic.P384().Add(mtx, mty, vcx, vcy)

	var cH [64]byte
	h.Reset()
	h.Write(m)
	h.Write(elliptic.Marshal(elliptic.P384(), grx, gry)) // const length
	h.Write(elliptic.Marshal(elliptic.P384(), hrx, hry)) // const length
	h.Sum(cH[:0])
	return subtle.ConstantTimeCompare(cH[:48], c) == 1
}

func hashToCurve(m []byte) (x, y *big.Int) {
	// Construction from <https://www.iacr.org/archive/crypto2010/62230238/62230238.pdf> section 4
	// "[...] if h1, h2 are two hash functions in the random oracle model, then
	// the hash function H defined by
	//     H(m) := f(h1(m)) + f(h2(m))
	// is indifferentiable from a random oracle into the elliptic curve."
	// Here, we use SHA512, SHA384, the icart function, and P384.
	// SHA384 and SHA512 are initialized differently according to
	// <http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf>.
	h1, h2 := sha512.Sum512(m), sha512.Sum384(m)
	var x1, y1, x2, y2, u big.Int
	u.SetBytes(h1[:48])
	icart.ToP384(&x1, &y1, &u)
	u.SetBytes(h2[:48])
	icart.ToP384(&x2, &y2, &u)
	return elliptic.P384().Add(&x1, &y1, &x2, &y2)
}
