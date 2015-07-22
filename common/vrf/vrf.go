// Package vrf implements a verifiable random function using SHA384,
// SHA512-384, P-384 and the Icart function.
package vrf

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

const (
	PublicKeySize    = 32
	SecretKeySize    = 32 + PublicKeySize
	Size             = 32
	intermediateSize = PublicKeySize
	ProofSize        = 32 + 32 + intermediateSize
)

var p25519, _ = new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

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

	ecsk := sha256.Sum256(sk[:32])
	var ecpk [32]byte
	curve25519.ScalarBaseMult(&ecpk, &ecsk)
	copy(sk[32:32+PublicKeySize], ecpk[0:PublicKeySize])
	return pk[:], sk, nil
}

// Compute returns the value of a veirifiable random function of m using key k.
// H(m, H'(m)^k). TODO: I think length extension does not matter because the
// value we are trying to hide is last, but maybe we should double up anyway?
func Compute(m []byte, sk *[SecretKeySize]byte) []byte {
	vrf := sha256.New()
	vrf.Write(compute(m, sk)[:]) // const length: Size
	vrf.Write(m)
	return vrf.Sum(nil)
}

func compute(m []byte, sk *[SecretKeySize]byte) *[32]byte {
	k := sha256.Sum256(sk[:32])
	hm := hashToCurve(m)
	curve25519.ScalarMult(hm, &k, hm)
	return hm
}

func swapEndian(k []byte) {
	for i := 0; i < len(k)/2; i++ {
		k[i], k[len(k)-i-1] = k[len(k)-i-1], k[i]
	}
}

// Prove returns a proof that will pass Verify, len(proof)=ProofSize.
func Prove(m []byte, sk *[SecretKeySize]byte) []byte {
	k := sha256.Sum256(sk[:32])
	hskForR := sha256.Sum256(sk[:64])
	var hr, gr, r, cH [32]byte

	hash := sha256.New()
	hash.Write(hskForR[:])
	hash.Write(m)
	hash.Sum(r[:0])

	curve25519.ScalarBaseMult(&gr, &r)
	h := hashToCurve(m)
	curve25519.ScalarMult(&hr, h, &r)

	hash.Reset()
	hash.Write(gr[:])
	hash.Write(hr[:])
	hash.Write(m)
	hash.Sum(cH[:0])

	// FIXME: move away from math.big, it is not constant-time
	var t, c big.Int
	swapEndian(k[:]) // math.big is big-endian, Curve25519 is little-endian
	swapEndian(cH[:])
	c.SetBytes(cH[:32]) // c
	c.Mul(&c, new(big.Int).SetBytes(k[:]))
	c.Mod(&c, p25519) // c*k
	t.SetBytes(r[:])
	t.Sub(&t, &c)
	t.Mod(&t, p25519) // r - c*k

	var ret [ProofSize]byte
	copy(ret[:32], cH[:32])
	copy(ret[:32], t.Bytes())
	swapEndian(ret[0:32])
	swapEndian(ret[32:64])
	copy(ret[64:96], compute(m, sk)[:])
	return ret[:]
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
func Verify(pkBytes, m, vrfBytes, proof []byte) bool {
	if len(proof) != ProofSize || len(vrfBytes) != Size || len(pkBytes) != PublicKeySize {
		return false
	}
	var pk, c, t, vrf [32]byte
	copy(vrf[:], vrfBytes)
	copy(pk[:], pkBytes)
	copy(c[:32], proof[:32])
	copy(t[:32], proof[32:64])
	vIntermediate := proof[64:]

	h := sha256.New()
	h.Write(vIntermediate) // const length
	h.Write(m)
	if subtle.ConstantTimeCompare(h.Sum(nil)[:32], vrf[:32]) != 1 {
		return false
	}

	var Pc, gt, gr, mt, vc, hr [32]byte
	curve25519.ScalarMult(&Pc, &pk, &c)
	curve25519.ScalarBaseMult(&gt, &t)
	curve25519.Add(&gr, &gt, &Pc)
	hm := hashToCurve(m)
	curve25519.ScalarMult(&mt, hm, &t)
	curve25519.ScalarMult(&mt, hm, &t)
	curve25519.ScalarMult(&vc, &vrf, &c)
	curve25519.Add(&hr, &mt, &vc)

	var cH [32]byte
	h.Write(m)
	h.Write(gr[:]) // const length
	h.Write(hr[:]) // const length
	h.Reset()
	h.Sum(cH[:0])
	return subtle.ConstantTimeCompare(cH[:], c[:]) == 1
}

func hashToCurve(m []byte) (x *[32]byte) {
	h := sha256.Sum256(m)
	var p [32]byte
	extra25519.RepresentativeToPublicKey(&p, &h)
	return &p
}
