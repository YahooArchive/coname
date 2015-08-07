// Copyright 2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

package merkletree

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/yahoo/coname/common"
)

const (
	IntermediateNodeIdentifier = 'I'
	LeafIdentifier             = 'L'
)

// TODO switch to CONIKS spec

func HashIntermediateNode(prefixBits []bool, childHashes *[2][common.HashBytes]byte) []byte {
	buf := make([]byte, 5)
	buf[0] = IntermediateNodeIdentifier
	binary.LittleEndian.PutUint32(buf[1:], uint32(len(prefixBits)))
	h := sha256.New()
	h.Write(buf)
	h.Write(childHashes[0][:])
	h.Write(childHashes[1][:])
	h.Write(common.ToBytes(prefixBits))
	return h.Sum(nil)
}

func HashLeaf(indexBytes []byte, commitment []byte) []byte {
	h := sha256.New()
	h.Write([]byte{LeafIdentifier})
	h.Write(indexBytes)
	h.Write(commitment)
	return h.Sum(nil)
}
