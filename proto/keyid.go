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

package proto

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// KeyID computes the ID of public key.
func KeyID(sv *PublicKey) uint64 {
	var h [8]byte
	sha3.ShakeSum256(h[:], MustMarshal(sv))
	return binary.LittleEndian.Uint64(h[:8])
}
