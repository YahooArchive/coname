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
func VerifySignature(pk *proto.PublicKey, message []byte, sig []byte) bool {
	switch {
	case pk.Ed25519 != nil:
		var edpk [32]byte
		var edsig [64]byte
		copy(edpk[:], pk.Ed25519[:])
		copy(edsig[:], sig)
		return ed25519.Verify(&edpk, message, &edsig)
	default:
		return false
	}
}
