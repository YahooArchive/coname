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

	"github.com/yahoo/coname/server/kv"
)

const (
	NodePrefix       = 'T'
	AllocCounterKey  = "AC"
	NodeKeyDelimiter = 'N'
	IndexBytes       = 32
	IndexBits        = IndexBytes * 8
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
	childIds    [2]uint64          // 0 if the node is a leaf
	childHashes [2][HashBytes]byte // zeroed if the node is a leaf
	commitment  []byte             // nil if the node is not a leaf
	indexBytes  []byte             // nil if the node is not a leaf
}

type node struct {
	diskNode
	prefixBits []bool
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

// Lookup looks up the entry at a particular index in the snapshot.
// In case it's present, returns:                      commitment, nil,   sibling hashes, nil
// In case this index hits an empty branch, returns:   nil,        nil,   sibling hashes, nil
// In case this index hits a mismatched leaf, returns: commitment, index, sibling hashes, nil
func (snapshot *Snapshot) Lookup(indexBytes []byte) (
	commitment []byte, proofIndex []byte, proof [][]byte, err error,
) {
	if len(indexBytes) != IndexBytes {
		return nil, nil, nil, fmt.Errorf("Wrong index length")
	}
	n, err := snapshot.loadRoot()
	if err != nil {
		return
	}
	if n == nil {
		// Special case: The tree is empty
		return nil, nil, nil, nil
	}
	indexBits := ToBits(IndexBits, indexBytes)
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for !n.isLeaf {
		descendingRight := indexBits[len(n.prefixBits)]
		siblingHash := n.childHashes[BitToIndex(!descendingRight)]
		proof = append(proof, siblingHash[:])
		childPointer, err := snapshot.tree.getChildPointer(n, descendingRight)
		if err != nil {
			return nil, nil, nil, err
		}
		n = *childPointer
		if n == nil {
			// There's no leaf with this index. The proof will now function as a proof of absence to the
			// client by showing a valid hash path down to the nearest sibling, which creates the correct
			// root hash when this branch's hash is nil.
			return nil, nil, proof, nil
		}
	}
	// Once a leaf node is reached, compare the entire index stored in the leaf node.
	if bytes.Equal(indexBytes, n.indexBytes) {
		// The leaf exists: we will simply return the value hash
	} else {
		// There is no leaf with the requested index. To prove it, we need to return the mismatching
		// leaf node along with its Merkle proof.
		proofIndex = append([]byte(nil), n.indexBytes...) // Copy the index bytes
	}
	return n.commitment, proofIndex, proof, nil
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
func (snapshot *NewSnapshot) Set(indexBytes []byte, commitment []byte) (err error) {
	if len(indexBytes) != IndexBytes {
		return fmt.Errorf("Wrong index length")
	}
	commitment = append([]byte(nil), commitment...) // Make a copy of commitment
	indexBits := ToBits(IndexBits, indexBytes)
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
				indexBytes: append([]byte(nil), indexBytes...), // Make a copy of indexBytes
				commitment: commitment,
			},
			prefixBits: indexBits[:position],
		}
	} else if bytes.Equal((*nodePointer).indexBytes, indexBytes) {
		// We have an existing leaf at this index; just replace the value
		(*nodePointer).commitment = commitment
	} else {
		// We have a different leaf with a matching prefix. We'll have to create new intermediate nodes.
		oldLeaf := *nodePointer
		oldLeafIndexBits := ToBits(IndexBits, oldLeaf.indexBytes)
		// Create a new intermediate node for each bit that has now become shared.
		for oldLeafIndexBits[position] == indexBits[position] {
			newNode := &node{
				diskNode: diskNode{
					isLeaf: false,
				},
				prefixBits: indexBits[:position],
			}
			*nodePointer, nodePointer = newNode, &newNode.children[BitToIndex(indexBits[position])]
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
				indexBytes: append([]byte(nil), indexBytes...), // Make a copy of the index
				commitment: commitment,
			},
			prefixBits: indexBits[:position+1],
		}
		// Move the old leaf's index down
		oldLeaf.prefixBits = oldLeafIndexBits[:position+1]
		splitNode.children[BitToIndex(indexBits[position])] = newLeaf
		splitNode.children[BitToIndex(oldLeafIndexBits[position])] = oldLeaf
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
func (t *MerkleTree) flushNode(n *node, wb kv.Batch) (id uint64, hash [HashBytes]byte) {
	for i := 0; i < 2; i++ {
		if n.children[i] != nil {
			n.childIds[i], n.childHashes[i] = t.flushNode(n.children[i], wb)
		}
	}
	id = t.allocNodeId()
	t.store(id, n, wb)
	copy(hash[:], n.hash())
	return
}

func (t *MerkleTree) store(id uint64, n *node, wb kv.Batch) {
	wb.Put(t.serializeKey(id, n.prefixBits), n.serialize())
}

func (t *MerkleTree) getChildPointer(n *node, isRight bool) (**node, error) {
	ix := BitToIndex(isRight)
	if n.childIds[ix] != 0 && n.children[ix] == nil {
		// lazy-load the child
		childIndex := append(n.prefixBits, isRight)
		child, err := t.loadNode(n.childIds[ix], childIndex)
		if err != nil {
			return nil, err
		}
		n.children[ix] = child
	}
	return &n.children[ix], nil
}

func (t *MerkleTree) serializeKey(id uint64, prefixBits []bool) []byte {
	indexBytes := ToBytes(prefixBits)
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
		return append(append([]byte{LeafIdentifier}, n.indexBytes...), n.commitment...)
	} else {
		buf := make([]byte, 1, 1+2*8+2*HashBytes)
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
		n.indexBytes = buf[:IndexBytes]
		buf = buf[IndexBytes:]
		n.commitment = buf[:HashBytes]
		buf = buf[HashBytes:]
		if len(buf) != 0 {
			log.Panic("bad leaf node length")
		}
	} else if buf[0] == IntermediateNodeIdentifier {
		n.isLeaf = false
		buf = buf[1:]
		for i := 0; i < 2; i++ {
			n.childIds[i] = uint64(binary.LittleEndian.Uint64(buf[:8]))
			buf = buf[8:]
			copy(n.childHashes[i][:], buf[:HashBytes])
			buf = buf[HashBytes:]
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
		return HashLeaf(n.indexBytes, n.commitment)
	}
}
