package vrf

import (
	"bytes"
	"testing"
//	"fmt"
	"encoding/hex"
)

func TestHonestComplete(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := []byte("alice")
	aliceVRF := Compute(alice, sk)
	aliceVRFFromProof, aliceProof := Prove(alice, sk)

	// fmt.Printf("pk:           %X\n", pk)
	// fmt.Printf("sk:           %X\n", *sk)
	// fmt.Printf("alice(bytes): %X\n", alice)
	// fmt.Printf("aliceVRF:     %X\n", aliceVRF)
	// fmt.Printf("aliceProof:   %X\n", aliceProof)

	if !Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("Gen -> Compute -> Prove -> Verify -> FALSE")
	}
	if !bytes.Equal(aliceVRF, aliceVRFFromProof) {
		t.Errorf("Compute != Prove")
	}
}

func TestFlipBitForgery(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := []byte("alice")
	for i := 0; i < 32; i++ {
		for j := uint(0); j < 8; j++ {
			aliceVRF := Compute(alice, sk)
			aliceVRF[i] ^= 1 << j
			_, aliceProof := Prove(alice, sk)
			if Verify(pk, alice, aliceVRF, aliceProof) {
				t.Fatalf("forged by using aliceVRF[%d]^=%d:\n (sk=%x)", i, j, sk)
			}
		}
	}
}

func sampleVectorTest(pks, aliceVRFs, aliceProofs string, t *testing.T) {
	pk, _ := hex.DecodeString(pks)
	aliceVRF, _ := hex.DecodeString(aliceVRFs)
	aliceProof, _ := hex.DecodeString(aliceProofs)

	alice := []byte{97, 108, 105, 99, 101}

	// Positive test case
	if !Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("TestSampleVectors HonestVector Failed")
	}

	// Negative test cases - try increment the first byte of every vector
	pk[0]++
	if Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("TestSampleVectors ForgedVector (pk modified) Passed")
	}
	pk[0]--

	alice[0]++
	if Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("TestSampleVectors ForgedVector (alice modified) Passed")
	}
	alice[0]--

	aliceVRF[0]++
	if Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("TestSampleVectors ForgedVector (aliceVRF modified) Passed")
	}
	aliceVRF[0]--

	aliceProof[0]++
	if Verify(pk, alice, aliceVRF, aliceProof) {
		t.Errorf("TestSampleVectors ForgedVector (aliceProof modified) Passed")
	}
	aliceProof[0]--
}

func TestSampleVectorSets(t *testing.T) {

	var pk, aliceVRF, aliceProof string

	// Following sets of test vectors are collected from TestHonestComplete(),
	// and are used for testing the JS implementation of vrf.verify()
	// Reference: https://github.com/yahoo/end-to-end/pull/58

	pk = "885f642c8390293eb74d08cf38d3333771e9e319cfd12a21429eeff2eddeebd2"
	aliceVRF = "7a18a2c2568e3521e312859224cb5d754c2ef8ec210359e40fe990a641b34d68"
	aliceProof = "027a18a2c2568e3521e312859224cb5d754c2ef8ec210359e40fe990a641b34d683bd3b252b12af52b02cd4903b3374eeb0b0a1599f320af40ebda6f5072843ce5983b21d979faf243e11eae1985ba6e56"
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = "73d1a8f18e3248488c2cf1eebb4dc3ff92405eb709afaac1f9bb573018f95b66"
	aliceVRF = "62efbc924372177ecf2774abea58c59b29d393d276485778b8703d8340c321d1"
	aliceProof = "0362efbc924372177ecf2774abea58c59b29d393d276485778b8703d8340c321d11192a5ea552af8d11d4514d5869534ec0b89bac6a858de6cde27f4a64333a772cfd4f151751034fb8abdedf3ef26ee5c"
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = "90b584ca7e88753a35010cf082269f92b29ba0d2820419dcf94ae386ddf31557"
	aliceVRF = "f4daa079238229b9723d8965b501a5a12b63802a45057e3fe9b58d5fe581bc3e"
	aliceProof = "02f4daa079238229b9723d8965b501a5a12b63802a45057e3fe9b58d5fe581bc3e2e66e61c08d9a77f197f8b138a3a4709034f7eba891bda46036c44efbf960273087e749191ce70bd3584908f677d346e"
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

}

func BenchmarkCompute(b *testing.B) {
	_, sk, err := GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	alice := []byte("alice")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Compute(alice, sk)
	}
}

func BenchmarkProve(b *testing.B) {
	_, sk, err := GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	alice := []byte("alice")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Prove(alice, sk)
	}
}

func BenchmarkVerify(b *testing.B) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	alice := []byte("alice")
	aliceVRF := Compute(alice, sk)
	_, aliceProof := Prove(alice, sk)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Verify(pk, alice, aliceVRF, aliceProof)
	}
}
