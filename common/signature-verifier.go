// Copyright 2014-2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

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
		var n uint32
		for idx, ver := range verifier.Threshold.Verifiers {
			if hasSigned(idx, ver, message, sigs) {
				n++
			}
		}
		return n >= verifier.Threshold.Threshold
	default:
		return false
	}
}

func hasSigned(idx int, ver *proto.SignatureVerifier, message []byte, sigs *proto.ThresholdSignature) bool {
	for i := 0; i < len(sigs.Signature) && i < len(sigs.KeyIndex); i++ {
		if sigs.KeyIndex[i] == uint32(idx) && VerifySignature(ver, message, sigs.Signature[i]) {
			return true
		}
	}
	return false
}
