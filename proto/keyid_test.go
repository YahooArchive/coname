package proto

import "testing"

func TestKeyID(t *testing.T) {

	pk := []byte{108, 121, 82, 46, 112, 133, 74, 243, 72, 208, 82, 162, 56, 223, 221, 115, 5, 228, 171, 34, 69, 211, 87, 96, 159, 119, 223, 186, 41, 220, 44, 62}
	ppk := &PublicKey{
		PubkeyType: &PublicKey_Ed25519{Ed25519: pk[:]},
	}
	id := KeyID(ppk)
	if got, want := id, uint64(15615436926645791512); got != want {
		t.Fatalf("KeyID() got %v, wanted %v", got, want)
	}
}
