package common

import (
	"github.com/agl/ed25519"
	"github.com/yahoo/coname/proto"
)

// VerifySignature returns true iff sig is a valid signature of message by
// verifier.  verifier, message, sig : &const // none of the inputs are
// modified
func VerifySignature(verifier *proto.SignatureVerifier, message []byte, sig []byte) bool {
	switch {
	case verifier.Ed25519 != nil:
		var pk [32]byte
		var copySig [64]byte
		copy(pk[:], verifier.Ed25519[:])
		copy(copySig[:], sig)
		return ed25519.Verify(&pk, message, &copySig)
	case verifier.Threshold != nil:
		sigs := new(proto.ThresholdSignature)
		if err := sigs.Unmarshal(sig); err != nil {
			return false
		}
		remaining := verifier.Threshold.Threshold
	next_key:
		for idx, ver := range verifier.Threshold.Verifiers {
			for i := 0; i < len(sigs.Signature) && i < len(sigs.KeyIndex); i++ {
				if sigs.KeyIndex[i] == idx && VerifySignature(ver, message, sigs.Signature[i]) {
					remaining--
					if remaining == 0 {
						return true
					}
					continue next_key
				}
			}
		}
		return remaining == 0
	default:
		return false
	}
}
