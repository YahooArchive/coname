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

	pk = "7855A75D36787990CB7A35457FAECC045CDBA7D15ADB9A0C6EAED44E1EB1A572"
	aliceVRF = "6A0B14896F14BA6D99B51B20EB4DEEA9640D560C0EEBA1436428C3E9441637FE"
	aliceProof = "036A0B14896F14BA6D99B51B20EB4DEEA9640D560C0EEBA1436428C3E9441637FEF122A17978903A614548C87D79FDC4C20DB8DFF7FBC7A3D9BA7FD7BAD09BA38BBA670E7316415FE3068E7ED88B6446BD"
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = "F40DEF436C6FE4606E2973DC54420A4F99E45386DA2D8941E0DD5043E7DFBB1D"
	aliceVRF = "C976FBCB13CAC508FD23CE28E531E6CCF76E42659189BE9CA65AF5B7B513137A"
	aliceProof = "02C976FBCB13CAC508FD23CE28E531E6CCF76E42659189BE9CA65AF5B7B513137A899C57441ADAD75C7C10F4820D2D69110B26A276654946A9B4C8FBA790F279FF61D08956739F2FC471FD00D5AB122B47"
	sampleVectorTest(pk, aliceVRF, aliceProof, t)

	pk = "366A13953268020F3A7A95129148B94CBCA1B211B47FD73CE662FBA6779E2E4D"
	aliceVRF = "48CECDE0BE4B7B7F7E97E5002830AE23060BCF1122D816FE1D05EC73D58C9DA1"
	aliceProof = "0348CECDE0BE4B7B7F7E97E5002830AE23060BCF1122D816FE1D05EC73D58C9DA147650233F751728843AFC69B6F71EC1C0B23B9FEFEB19AEC951D42144625CBACA03A624579263430AA15BE249B73C383"
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
