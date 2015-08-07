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

package client

import (
	"fmt"

	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
)

func RecomputeHash(treeNonce []byte, node common.MerkleNode) ([]byte, error) {
	return recomputeHash(treeNonce, []bool{}, node)
}

// assumes ownership of the array underlying prefixBits
func recomputeHash(treeNonce []byte, prefixBits []bool, node common.MerkleNode) ([]byte, error) {
	if node.IsEmpty() {
		return common.HashEmptyBranch(treeNonce, prefixBits), nil
	} else if node.IsLeaf() {
		return common.HashLeaf(treeNonce, node.Index(), node.Depth(), node.Value()), nil
	} else {
		var childHashes [2][common.HashBytes]byte
		for i := 0; i < 2; i++ {
			rightChild := i == 1
			h := node.ChildHash(rightChild)
			if h == nil {
				ch, err := node.Child(rightChild)
				if err != nil {
					return nil, err
				}
				h, err = recomputeHash(treeNonce, append(prefixBits, rightChild), ch)
				if err != nil {
					return nil, err
				}
			}
			copy(childHashes[i][:], h)
		}
		return common.HashInternalNode(prefixBits, &childHashes), nil
	}
}

type ReconstructedNode struct {
	isLeaf bool
	depth  int

	children [2]struct {
		// Only one of the following two may be set
		Omitted []byte
		Present *ReconstructedNode
	}

	index []byte
	value []byte
}

func ReconstructTree(trace *proto.TreeProof, lookupIndexBits []bool) (*ReconstructedNode, error) {
	return reconstructBranch(trace, lookupIndexBits, 0), nil
}

func reconstructBranch(trace *proto.TreeProof, lookupIndexBits []bool, depth int) *ReconstructedNode {
	if depth == len(trace.Neighbors) {
		if trace.ExistingEntryHash == nil {
			return nil
		} else {
			return &ReconstructedNode{
				isLeaf: true,
				depth:  depth,
				index:  trace.ExistingIndex,
				value:  trace.ExistingEntryHash,
			}
		}
	} else {
		node := &ReconstructedNode{
			isLeaf: false,
			depth:  depth,
		}
		presentChild := lookupIndexBits[depth]
		node.children[common.BitToIndex(presentChild)].Present = reconstructBranch(trace, lookupIndexBits, depth+1)
		node.children[common.BitToIndex(!presentChild)].Omitted = trace.Neighbors[depth]
		return node
	}
}

var _ common.MerkleNode = (*ReconstructedNode)(nil)

func (n *ReconstructedNode) IsEmpty() bool {
	return n == nil
}

func (n *ReconstructedNode) IsLeaf() bool {
	return n.isLeaf
}

func (n *ReconstructedNode) Depth() int {
	return n.depth
}

func (n *ReconstructedNode) ChildHash(rightChild bool) []byte {
	return n.children[common.BitToIndex(rightChild)].Omitted
}

func (n *ReconstructedNode) Child(rightChild bool) (common.MerkleNode, error) {
	// Give an error if the lookup algorithm tries to access anything the server didn't provide us.
	if n.children[common.BitToIndex(rightChild)].Omitted != nil {
		return nil, fmt.Errorf("can't access omitted node")
	}
	// This might still be nil if the branch is in fact empty.
	return n.children[common.BitToIndex(rightChild)].Present, nil
}

func (n *ReconstructedNode) Index() []byte {
	return n.index
}

func (n *ReconstructedNode) Value() []byte {
	return n.value
}
