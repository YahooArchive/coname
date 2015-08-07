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
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"sync"

	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
)

const (
	NodePrefix       = 'T'
	AllocCounterKey  = "AC"
	NodeKeyDelimiter = 'N'
	SnapshotNrBytes  = 8
	IndexLengthBytes = 4
)

type MerkleTree struct {
	db              kv.DB
	nodeKeyPrefix   []byte
	allocCounterKey []byte

	allocMutex   sync.Mutex
	allocCounter uint64
}

// AccessMerkleTree opens the Merkle tree stored in the DB. There should never be two different
// MerkleTree objects accessing the same tree.
func AccessMerkleTree(db kv.DB, prefix []byte) (*MerkleTree, error) {
	// read the allocation count out of the DB
	allocCounterKey := append(append([]byte(nil), prefix...), AllocCounterKey...)
	val, err := db.Get(allocCounterKey)
	var allocCount uint64
	if err == db.ErrNotFound() {
		allocCount = 0
	} else if err != nil {
		return nil, err
	} else if len(val) != 8 {
		log.Panicf("bad alloc counter")
	} else {
		allocCount = binary.LittleEndian.Uint64(val)
	}
	return &MerkleTree{
		db:              db,
		nodeKeyPrefix:   append(append([]byte(nil), prefix...), NodePrefix),
		allocCounterKey: allocCounterKey,
		allocCounter:    allocCount,
	}, nil
}

// Snapshot represents a particular (immutable) state of the tree. Changes are made by calling
// BeginModification(), updating the returned NewSnapshot, and then getting an updated Snapshot out
// from Flush().
type Snapshot struct {
	tree *MerkleTree
	Nr   uint64
}

type diskNode struct {
	isLeaf      bool
	childIds    [2]uint64                 // 0 if the node is a leaf
	childHashes [2][common.HashBytes]byte // zeroed if the node is a leaf
	value       []byte                    // nil if the node is not a leaf
	indexBytes  []byte                    // nil if the node is not a leaf
}

type node struct {
	diskNode
	prefixBits []bool   // Could be sliced (underlying array not owned) -- *don't* append to this!
	children   [2]*node // lazily loaded
}

// NewSnapshot represents a snapshot that is being built up in memory.
type NewSnapshot struct {
	Snapshot
	root *node
}

// GetSnapshot loads the snapshot with a particular ID. Use 0 for a new empty snapshot.
func (tree *MerkleTree) GetSnapshot(nr uint64) *Snapshot {
	// TODO: This can't actually determine whether the snapshot exists, since a missing entry might just
	// indicate an empty tree. Is that okay?
	return &Snapshot{tree, nr}
}

// GetRootHash gets the summary hash for the entire state of the tree.
func (snapshot *Snapshot) GetRootHash() ([]byte, error) {
	root, err := snapshot.loadRoot()
	if err != nil {
		return nil, err
	}
	return root.hash(), nil
}

type LookupTracingNode struct {
	tree  *MerkleTree
	trace *proto.TreeProof
	node  *node
}

func makeTracingNode(tree *MerkleTree, trace *proto.TreeProof, n *node) *LookupTracingNode {
	if n == nil {
		return nil
	} else {
		return &LookupTracingNode{tree, trace, n}
	}
}

var _ common.MerkleNode = (*LookupTracingNode)(nil)

func (n *LookupTracingNode) IsEmpty() bool {
	return n == nil
}

func (n *LookupTracingNode) IsLeaf() bool {
	return n.node.isLeaf
}

func (n *LookupTracingNode) Depth() int {
	return len(n.node.prefixBits)
}

func (n *LookupTracingNode) ChildHash(rightChild bool) []byte {
	return n.node.childHashes[common.BitToIndex(rightChild)][:]
}

func (n *LookupTracingNode) Child(rightChild bool) (common.MerkleNode, error) {
	if len(n.trace.Neighbors) != n.Depth() {
		log.Panicf("unexpected access pattern: at depth %v, have %v", n.Depth(), n.trace.Neighbors)
	}
	// Record the sibling hash for the trace
	n.trace.Neighbors = append(n.trace.Neighbors, n.ChildHash(!rightChild))

	// Return the child (may be nil)
	childPtr, err := n.tree.getChildPointer(n.node, rightChild)
	if err != nil {
		return nil, err
	}
	return makeTracingNode(n.tree, n.trace, *childPtr), nil
}

func (n *LookupTracingNode) Index() []byte {
	n.trace.ExistingIndex = n.node.indexBytes
	return n.node.indexBytes
}

func (n *LookupTracingNode) Value() []byte {
	n.trace.ExistingEntryHash = n.node.value
	return n.node.value
}

func (snapshot *Snapshot) Lookup(indexBytes []byte) (value []byte, trace *proto.TreeProof, err error) {
	root, err := snapshot.loadRoot()
	if err != nil {
		return nil, nil, err
	}
	trace = &proto.TreeProof{}
	var tracingRoot common.MerkleNode = makeTracingNode(snapshot.tree, trace, root)
	value, err = common.Lookup(tracingRoot, indexBytes)
	if err != nil {
		return nil, nil, err
	}
	return
}

// BeginModification creates a new snapshot to be built up in memory (doesn't actually touch the
// disk yet)
func (snapshot *Snapshot) BeginModification() (*NewSnapshot, error) {
	root, err := snapshot.loadRoot()
	if err != nil {
		return nil, err
	}
	return &NewSnapshot{*snapshot, root}, nil
}

// Set updates the leaf value at the index (or inserts it if it did not exist).
// In-memory: doesn't actually touch the disk yet.
func (snapshot *NewSnapshot) Set(indexBytes []byte, value []byte) (err error) {
	if len(indexBytes) != common.IndexBytes {
		return fmt.Errorf("Wrong index length")
	}
	value = append([]byte(nil), value...) // Make a copy of value
	indexBits := common.ToBits(common.IndexBits, indexBytes)
	nodePointer := &snapshot.root
	position := 0
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for *nodePointer != nil && !(*nodePointer).isLeaf {
		nodePointer, err = snapshot.tree.getChildPointer(*nodePointer, indexBits[position])
		if err != nil {
			return
		}
		position++
	}
	if *nodePointer == nil {
		// We've hit an empty branch where this leaf belongs -- put it there.
		*nodePointer = &node{
			diskNode: diskNode{
				isLeaf:     true,
				indexBytes: append([]byte{}, indexBytes...), // Make a copy of indexBytes
				value:      value,
			},
			prefixBits: indexBits[:position],
		}
	} else if bytes.Equal((*nodePointer).indexBytes, indexBytes) {
		// We have an existing leaf at this index; just replace the value
		(*nodePointer).value = value
	} else {
		// We have a different leaf with a matching prefix. We'll have to create new intermediate nodes.
		oldLeaf := *nodePointer
		oldLeafIndexBits := common.ToBits(common.IndexBits, oldLeaf.indexBytes)
		// Create a new intermediate node for each bit that has now become shared.
		for oldLeafIndexBits[position] == indexBits[position] {
			newNode := &node{
				diskNode: diskNode{
					isLeaf: false,
				},
				prefixBits: indexBits[:position],
			}
			*nodePointer, nodePointer = newNode, &newNode.children[common.BitToIndex(indexBits[position])]
			position++
		}
		// Create a new node at which the tree now branches.
		splitNode := &node{
			diskNode: diskNode{
				isLeaf: false,
			},
			prefixBits: indexBits[:position],
		}
		// Create the new leaf under the splitNode
		newLeaf := &node{
			diskNode: diskNode{
				isLeaf:     true,
				indexBytes: append([]byte{}, indexBytes...), // Make a copy of the index
				value:      value,
			},
			prefixBits: indexBits[:position+1],
		}
		// Move the old leaf's index down
		oldLeaf.prefixBits = oldLeafIndexBits[:position+1]
		splitNode.children[common.BitToIndex(indexBits[position])] = newLeaf
		splitNode.children[common.BitToIndex(oldLeafIndexBits[position])] = oldLeaf
		*nodePointer = splitNode
	}
	return nil
}

// Flush returns a newly usable Snapshot
func (snapshot *NewSnapshot) Flush(wb kv.Batch) (flushed *Snapshot) {
	if snapshot.root == nil {
		flushed = &Snapshot{snapshot.tree, 0}
	} else {
		rootId, _ := snapshot.tree.flushNode(snapshot.root, wb)
		flushed = &Snapshot{snapshot.tree, rootId}
	}
	allocCountVal := make([]byte, 8)
	binary.LittleEndian.PutUint64(allocCountVal, snapshot.tree.allocCounter)
	wb.Put(snapshot.tree.allocCounterKey, allocCountVal)
	return
}

//////// Node manipulation functions ////////

func (snapshot *Snapshot) loadRoot() (*node, error) {
	return snapshot.tree.loadNode(snapshot.Nr, []bool{})
}

func (tree *MerkleTree) allocNodeId() uint64 {
	tree.allocMutex.Lock()
	defer tree.allocMutex.Unlock()
	// The first ID should be 1 (need nonzero IDs)
	tree.allocCounter++
	return tree.allocCounter
}

func (tree *MerkleTree) loadNode(id uint64, prefixBits []bool) (*node, error) {
	nodeBytes, err := tree.db.Get(tree.serializeKey(id, prefixBits))
	if err == tree.db.ErrNotFound() {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else {
		n := deserializeNode(nodeBytes)
		return &node{
			diskNode:   n,
			prefixBits: prefixBits,
		}, nil
	}
}

// flush writes the updated nodes under this node to disk, returning the updated hash and ID of the
// node.
func (t *MerkleTree) flushNode(n *node, wb kv.Batch) (id uint64, hash [common.HashBytes]byte) {
	for i := 0; i < 2; i++ {
		if n.children[i] != nil {
			n.childIds[i], n.childHashes[i] = t.flushNode(n.children[i], wb)
		}
	}
	id = t.allocNodeId()
	t.storeNode(id, n, wb)
	copy(hash[:], n.hash())
	return
}

func (t *MerkleTree) storeNode(id uint64, n *node, wb kv.Batch) {
	wb.Put(t.serializeKey(id, n.prefixBits), n.serialize())
}

func (t *MerkleTree) getChildPointer(n *node, isRight bool) (**node, error) {
	ix := common.BitToIndex(isRight)
	if n.childIds[ix] != 0 && n.children[ix] == nil {
		// lazy-load the child. *don't* append to n.prefixBits!
		childIndex := append(append([]bool{}, n.prefixBits...), isRight)
		child, err := t.loadNode(n.childIds[ix], childIndex)
		if err != nil {
			return nil, err
		}
		n.children[ix] = child
	}
	return &n.children[ix], nil
}

func (t *MerkleTree) serializeKey(id uint64, prefixBits []bool) []byte {
	indexBytes := common.ToBytes(prefixBits)
	key := make([]byte, 0, len(t.nodeKeyPrefix)+len(indexBytes)+4+1+8)
	key = append(key, t.nodeKeyPrefix...)
	key = append(key, indexBytes...)
	binary.LittleEndian.PutUint32(key[len(key):len(key)+4], uint32(len(prefixBits)))
	key = key[:len(key)+4]
	key = append(key, NodeKeyDelimiter)
	// Use big-endian to make lexicographical order correspond to creation order
	binary.BigEndian.PutUint64(key[len(key):len(key)+8], uint64(id))
	key = key[:len(key)+8]
	return key
}

func (n *diskNode) serialize() []byte {
	if n.isLeaf {
		return append(append([]byte{LeafIdentifier}, n.indexBytes...), n.value...)
	} else {
		buf := make([]byte, 1, 1+2*8+2*common.HashBytes)
		buf[0] = IntermediateNodeIdentifier
		for i := 0; i < 2; i++ {
			binary.LittleEndian.PutUint64(buf[len(buf):len(buf)+8], uint64(n.childIds[i]))
			buf = buf[:len(buf)+8]
			buf = append(buf, n.childHashes[i][:]...)
		}
		return buf
	}
}

func deserializeNode(buf []byte) (n diskNode) {
	if buf[0] == LeafIdentifier {
		n.isLeaf = true
		buf = buf[1:]
		n.indexBytes = buf[:common.IndexBytes]
		buf = buf[common.IndexBytes:]
		n.value = buf[:common.HashBytes]
		buf = buf[common.HashBytes:]
		if len(buf) != 0 {
			log.Panic("bad leaf node length")
		}
	} else if buf[0] == IntermediateNodeIdentifier {
		n.isLeaf = false
		buf = buf[1:]
		for i := 0; i < 2; i++ {
			n.childIds[i] = uint64(binary.LittleEndian.Uint64(buf[:8]))
			buf = buf[8:]
			copy(n.childHashes[i][:], buf[:common.HashBytes])
			buf = buf[common.HashBytes:]
		}
		if len(buf) != 0 {
			log.Panic("bad intermediate node length")
		}
	} else {
		log.Panicf("bad node identifier: %x", buf[0])
	}
	return
}

func (n *node) hash() []byte {
	if n.isLeaf {
		return HashIntermediateNode(n.prefixBits, &n.childHashes)
	} else {
		return HashLeaf(n.indexBytes, n.value)
	}
}
