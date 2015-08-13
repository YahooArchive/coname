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

package coname

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	HashBytes  = sha256.Size
	IndexBytes = sha256.Size
	IndexBits  = IndexBytes * 8
)

type MerkleNode interface {
	IsEmpty() bool

	IsLeaf() bool
	Depth() int

	// For intermediate nodes
	ChildHash(rightChild bool) []byte
	Child(rightChild bool) (MerkleNode, error)

	// For leaves
	Index() []byte
	Value() []byte
}

// Lookup looks up the entry at a particular index in the snapshot.
func Lookup(root MerkleNode, indexBytes []byte) (value []byte, err error) {
	if len(indexBytes) != IndexBytes {
		return nil, fmt.Errorf("Wrong index length")
	}
	if root.IsEmpty() {
		// Special case: The tree is empty.
		return nil, nil
	}
	n := root
	indexBits := ToBits(IndexBits, indexBytes)
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for !n.IsLeaf() {
		descendingRight := indexBits[n.Depth()]
		n, err = n.Child(descendingRight)
		if err != nil {
			return nil, err
		}
		if n.IsEmpty() {
			// There's no leaf with this index.
			return nil, nil
		}
	}
	// Once a leaf node is reached, compare the entire index stored in the leaf node.
	if bytes.Equal(indexBytes, n.Index()) {
		// The leaf exists: we will simply return the value.
		return n.Value(), nil
	} else {
		// There is no leaf with the requested index.
		return nil, nil
	}
}

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

func BitToIndex(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

// In each byte, the bits are ordered MSB to LSB
func ToBits(num int, bs []byte) []bool {
	bits := make([]bool, num)
	for i := 0; i < len(bits); i++ {
		bits[i] = (bs[i/8]<<uint(i%8))&(1<<7) > 0
	}
	return bits
}

// In each byte, the bits are ordered MSB to LSB
func ToBytes(bits []bool) []byte {
	bs := make([]byte, (len(bits)+7)/8)
	for i := 0; i < len(bits); i++ {
		if bits[i] {
			bs[i/8] |= (1 << 7) >> uint(i%8)
		}
	}
	return bs
}
