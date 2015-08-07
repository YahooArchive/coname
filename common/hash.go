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

package common

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	InternalNodeIdentifier = 'I'
	LeafIdentifier         = 'L'
	EmptyBranchIdentifier  = 'E'
)

// Differences from the CONIKS paper:
// * Add an identifier byte at the beginning to make it impossible for this to collide with leaves
//   or empty branches.
// * Add the prefix of the index, to protect against limited hash collisions or bugs.
// This gives H(k_internal || h_child0 || h_child1 || prefix || depth)
func HashInternalNode(prefixBits []bool, childHashes *[2][HashBytes]byte) []byte {
	h := sha256.New()
	h.Write([]byte{InternalNodeIdentifier})
	h.Write(childHashes[0][:])
	h.Write(childHashes[1][:])
	h.Write(ToBytes(prefixBits))
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(prefixBits)))
	h.Write(buf)
	return h.Sum(nil)
}

// This is the same as in the CONIKS paper.
// H(k_empty || nonce || prefix || depth)
func HashEmptyBranch(treeNonce []byte, prefixBits []bool) []byte {
	h := sha256.New()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(treeNonce)
	h.Write(ToBytes(prefixBits))
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(prefixBits)))
	h.Write(buf)
	return h.Sum(nil)
}

// This is the same as in the CONIKS paper: H(k_leaf || nonce || index || depth || value)
func HashLeaf(treeNonce []byte, indexBytes []byte, depth int, value []byte) []byte {
	h := sha256.New()
	h.Write([]byte{LeafIdentifier})
	h.Write(treeNonce)
	h.Write(indexBytes)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(depth))
	h.Write(buf)
	h.Write(value)
	return h.Sum(nil)
}
