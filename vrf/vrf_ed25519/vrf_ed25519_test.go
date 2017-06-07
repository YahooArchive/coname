/**
 * @license
 * Copyright 2017 Yahoo Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vrf_ed25519

import (
	"bytes"
	"encoding/hex"
	"testing"
	"crypto/rand"
	"io"
	"math/big"
	"fmt"

	"golang.org/x/crypto/ed25519"
	ed1 "github.com/r2ishiguro/vrf/go/vrf_ed25519/edwards25519"
	ed2 "github.com/yahoo/coname/ed25519/edwards25519"
)

const message = "message"

func TestGeScalarMult(t *testing.T) {
	var res1, res2 [32]byte

	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := ECVRF_hash_to_curve([]byte(message), pk)
	x := expandSecret(sk)
	h1 := GeScalarMult(c, x)
	h1.ToBytes(&res1)
	// copy c to h2
	var h2, h3 ed2.ExtendedGroupElement
	var ts [32]byte
	c.ToBytes(&ts)
	h2.FromBytes(&ts)
	ed2.GeScalarMult(&h3, x, &h2)
	h3.ToBytes(&res2)

	if !bytes.Equal(res1[:], res2[:]) {
		t.Errorf("GeScalarMult mismatch:\n%s\n%s\nx=\n%s\n", hex.Dump(res1[:]), hex.Dump(res2[:]), hex.Dump(x[:]))
	}
}

func TestGeAdd(t *testing.T) {
	var p1, p2 ed2.ProjectiveGroupElement
	var h1, h2, c2 ed2.ExtendedGroupElement
	var a1, a2, res1, res2, tmp [32]byte

	io.ReadFull(rand.Reader, tmp[:])
	c1 := ECVRF_hash_to_curve([]byte(message), tmp[:])

	io.ReadFull(rand.Reader, a1[:])
	io.ReadFull(rand.Reader, a2[:])
	c1.ToBytes(&tmp)
	c2.FromBytes(&tmp)
	ed2.GeDoubleScalarMultVartime(&p1, &a1, &c2, &[32]byte{})
	ed2.GeDoubleScalarMultVartime(&p2, &a2, &c2, &[32]byte{})
	p1.ToExtended(&h1)
	p2.ToExtended(&h2)
	ed2.GeAdd(&h1, &h1, &h2)
	h1.ToBytes(&res1)

	var v1, v2 ed1.ProjectiveGroupElement
	ed1.GeDoubleScalarMultVartime(&v1, &a1, c1, &[32]byte{})
	ed1.GeDoubleScalarMultVartime(&v2, &a2, c1, &[32]byte{})
	h3 := GeAdd(GeScalarMult(c1, &a1), GeScalarMult(c1, &a2))
	h3.ToBytes(&res2)
	if !bytes.Equal(res1[:], res2[:]) {
		t.Error("GeAdd mismatch")
	}
}

var extendedBaseEl = ed1.ExtendedGroupElement{
	ed1.FieldElement{25485296, 5318399, 8791791, -8299916, -14349720, 6939349, -3324311, -7717049, 7287234, -6577708},
	ed1.FieldElement{-758052, -1832720, 13046421, -4857925, 6576754, 14371947, -13139572, 6845540, -2198883, -4003719},
	ed1.FieldElement{-947565, 6097708, -469190, 10704810, -8556274, -15589498, -16424464, -16608899, 14028613, -5004649},
	ed1.FieldElement{6966464, -2456167, 7033433, 6781840, 28785542, 12262365, -2659449, 13959020, -21013759, -5262166},
}

func TestG(t *testing.T) {
	var res1, res2 [32]byte
	g := G()
	g.ToBytes(&res1)
	extendedBaseEl.ToBytes(&res2)

	if !bytes.Equal(res1[:], res2[:]) {
		t.Errorf("G mismatch")
	}
}

func toLittle(x []byte) *[32]byte {
	r := new([32]byte)
	for i := 0; i < 32; i++ {
		r[32 - i - 1] = x[i]
	}
	return r
}

func TestArith(t *testing.T) {
	q, _ := new(big.Int).SetString(qs, 16)

	var c [32]byte
/*
	// generate c randmly
	var cc [64]byte
	io.ReadFull(rand.Reader, cc[:])
	ed2.ScReduce(&c, &cc)
*/
	for {
		io.ReadFull(rand.Reader, c[:])
		if c[0] < 0x10 {
			// c < q
			break
		}
	}

	x := I2OSP(big.NewInt(1), N2)
	k := I2OSP(big.NewInt(4), N2)
	var z big.Int
	s := z.Mod(z.Sub(OS2IP(k), z.Mul(OS2IP(c[:]), OS2IP(x))), q)
	ss := I2OSP(s, N2)
	s1 := toLittle(ss)

	var s2, minusC2 [32]byte
	ed2.ScNeg(&minusC2, toLittle(c[:]))
	x2 := toLittle(x)
	k2 := toLittle(k)
	ed2.ScMulAdd(&s2, x2, &minusC2, k2)

	if !bytes.Equal(s1[:], s2[:]) {
		t.Errorf("Arith mismatch\n%s\n%s", hex.Dump(ss), hex.Dump(s2[:]))
	}
}

func DoTestECVRF(t *testing.T, pk, sk []byte, msg []byte, verbose bool) {
	pi, err := ECVRF_prove(pk, sk, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	res, err := ECVRF_verify(pk, pi, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Errorf("VRF failed")
	}

	// when everything get through
	if verbose {
		fmt.Printf("alpha: %s\n", hex.EncodeToString(msg))
		fmt.Printf("x: %s\n", hex.EncodeToString(sk))
		fmt.Printf("P: %s\n", hex.EncodeToString(pk))
		fmt.Printf("pi: %s\n", hex.EncodeToString(pi))
		fmt.Printf("vrf: %s\n", hex.EncodeToString(ECVRF_proof2hash(pi)))

		r, c, s, err := ECVRF_decode_proof(pi)
		if err != nil {
			t.Fatal(err)
		}
		// u = (g^x)^c * g^s = P^c * g^s
		var u ed1.ProjectiveGroupElement
		P := OS2ECP(pk, pk[31] >> 7)
		ed1.GeDoubleScalarMultVartime(&u, c, P, s)
		fmt.Printf("r: %s\n", hex.EncodeToString(ECP2OS(r)))
		fmt.Printf("c: %s\n", hex.EncodeToString(c[:]))
		fmt.Printf("s: %s\n", hex.EncodeToString(s[:]))
		fmt.Printf("u: %s\n", hex.EncodeToString(ECP2OSProj(&u)))
	}
}

const howMany = 1000

func TestECVRF(t *testing.T) {
	for i := howMany; i > 0; i-- {
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		var msg [32]byte
		io.ReadFull(rand.Reader, msg[:])
		DoTestECVRF(t, pk, sk, msg[:], false)
	}
}

const pks = "885f642c8390293eb74d08cf38d3333771e9e319cfd12a21429eeff2eddeebd2"
const sks = "1fcce948db9fc312902d49745249cfd287de1a764fd48afb3cd0bdd0a8d74674885f642c8390293eb74d08cf38d3333771e9e319cfd12a21429eeff2eddeebd2"

// old keys -- must fail
//const sks = "c4d50101fc48c65ea496105e5f0a43a67636972d0186edfb9445a2d3377e8b9c8e6fb0fd096402527e7c2375255093975324751f99ef0b7db014eb7e311befb5"
//const pks = "8e6fb0fd096402527e7c2375255093975324751f99ef0b7db014eb7e311befb5"

func TestECVRFOnce(t *testing.T) {
	pk, _ := hex.DecodeString(pks)
	sk, _ := hex.DecodeString(sks)
	m := []byte(message)
	DoTestECVRF(t, pk, sk, m, true)

	h := ECVRF_hash_to_curve(m, pk)
	fmt.Printf("h: %s\n", hex.EncodeToString(ECP2OS(h)))
}

func TestHashToCurve(t *testing.T) {
	var m [32]byte
	pk, _ := hex.DecodeString(pks)
	for i := 0; i < 1000; i++ {
		io.ReadFull(rand.Reader, m[:])
		P := ECVRF_hash_to_curve(m[:], pk)
		// test P on curve by P^order = infinity
		var infs [32]byte
		inf := GeScalarMult(P, IP2F(q))
		inf.ToBytes(&infs)
		if infs != [32]byte{1} {
			t.Fatalf("OS2ECP: not valid curve")
		}
	}
}
