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
	"crypto/sha256"
	"encoding/binary"

	"github.com/yahoo/coname/proto"
)

// RatifierID computes the ID of a retifier by the hash-of-public-key convention.
func RatifierID(sv *proto.SignatureVerifier) uint64 {
	h := sha256.Sum256(proto.MustMarshal(sv))
	return binary.LittleEndian.Uint64(h[:8])
}
