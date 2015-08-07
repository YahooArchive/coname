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

func RecomputeHash(node common.MerkleNode) []byte {
	panic("TODO")
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

func ReconstructTree(trace *proto.TreeProof, leafIndex, leafValue []byte) (*ReconstructedNode, error) {
	return reconstructBranch(trace, leafIndex, leafValue, 0), nil
}

func reconstructBranch(trace *proto.TreeProof, leafIndex, leafValue []byte, depth int) *ReconstructedNode {
	if depth == len(trace.Neighbors) {
		return &ReconstructedNode{
			isLeaf: true,
			depth:  depth,
			index:  leafIndex,
			value:  leafValue,
		}
	} else {
		node := &ReconstructedNode{
			isLeaf: false,
			depth:  depth,
		}
		presentChild := common.ToBits(common.IndexBits, leafIndex)[depth]
		node.children[common.BitToIndex(presentChild)].Present = reconstructBranch(trace, leafIndex, leafValue, depth+1)
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
