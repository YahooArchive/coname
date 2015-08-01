package vrf

import (
	"github.com/davecheney/profile"
	"testing"
)

func TestHonestComplete(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := []byte("alice")
	aliceVRF := Compute(alice, sk)
	aliceProof := Prove(alice, sk)
	if !Verify(pk, alice, aliceVRF, aliceProof) {
		t.Fatalf("Gen -> Compute -> Prove -> Verify -> FALSE")
	}
}

func TestHonestComplete100(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	TestHonestComplete(t)
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
			aliceProof := Prove(alice, sk)
			if Verify(pk, alice, aliceVRF, aliceProof) {
				t.Fatalf("forged by using aliceVRF[%d]^=%d:\n (sk=%x)", i, j, sk)
			}
		}
	}
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
	defer profile.Start(profile.CPUProfile).Stop()
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
	aliceProof := Prove(alice, sk)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Verify(pk, alice, aliceVRF, aliceProof)
	}
}
