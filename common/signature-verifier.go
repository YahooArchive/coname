package coname

import (
	"github.com/agl/ed25519"
	"github.com/yahoo/coname/proto"
)

// Verify returns true iff sig is a valid signature of message by verifier.
// verifier, message, sig : &const // none of the inputs are modified
func Verify(verifier *proto.SignatureVerifier, message []byte, sig []byte) bool {
	switch {
	case verifier.Ed25519 != nil:
		var pk [32]byte
		var copySig [64]byte
		copy(pk[:], verifier.Ed25519[:])
		copy(copySig[:], sig)
		return ed25519.Verify(&pk, message, &copySig)
	case verifier.Threshold != nil:
		sigs := new(ThresholdSignature)
		if err := sigs.Unmarshal(sig); err != nil {
			return false
		}
		remaining := verifier.Threshold.Threshold
		for i := 0; i < len(sigs.Signature) && i < len(sigs.KeyIndex) && remaining > 0; i++ {
			if sigs.KeyIndex[i] < len(verifier.Verifiers) &&
				Verify(verifier.Verifiers[sigs.KeyIndex[i]], message, sigs.Signature[i]) {
				remaining--
			}
		}
		return remaining == 0
	default:
		return false
	}
}
