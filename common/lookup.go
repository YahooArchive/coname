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
	"bytes"
	"crypto/sha256"
	"fmt"
)

const (
	HashBytes  = sha256.Size
	IndexBytes = sha256.Size
	IndexBits  = IndexBytes * 8
)

type MerkleNode interface {
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
	if root == nil {
		// Special case: The tree is empty.
		return nil, nil
	}
	n := root
	indexBits := ToBits(IndexBits, indexBytes)
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for !n.IsLeaf() {
		descendingRight := indexBits[n.Depth()]
		n, err := n.Child(descendingRight)
		if err != nil {
			return nil, err
		}
		if n == nil {
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
