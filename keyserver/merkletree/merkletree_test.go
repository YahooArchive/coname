// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
)

var treeNonce []byte = []byte("NONCE NONCE NONCE")

func withDB(f func(kv.DB)) {
	dir, err := ioutil.TempDir("", "merkletree")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	f(leveldbkv.Wrap(db))
}

func verifyProof(s *Snapshot, index, value []byte, proof *proto.TreeProof) {
	reconstructed, err := coname.ReconstructTree(proof, coname.ToBits(coname.IndexBits, index))
	if err != nil {
		panic(err)
	}
	redoneLookup, err := coname.TreeLookup(reconstructed, index)
	if err != nil {
		panic(err)
	}
	if got, want := redoneLookup, value; !bytes.Equal(got, want) {
		log.Panicf("reconstructed lookup got different result: %v rather than %v", got, want)
	}
	recomputedHash, err := coname.RecomputeHash(treeNonce, reconstructed)
	if err != nil {
		panic(err)
	}
	rootHash, err := s.GetRootHash()
	if err != nil {
		panic(err)
	}
	if got, want := recomputedHash, rootHash; !bytes.Equal(got, want) {
		log.Panicf("reconstructed hash differed: %x rather than %x", got, want)
	}
}

func TestOneEntry(t *testing.T) {
	withDB(func(db kv.DB) {
		m, err := AccessMerkleTree(db, nil, treeNonce)
		if err != nil {
			panic(err)
		}
		e := m.GetSnapshot(0)
		index := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		val1, proof, err := e.Lookup(index)
		if val1 != nil || proof.ExistingIndex != nil || proof.ExistingEntryHash != nil || err != nil {
			panic("bad lookup in empty tree")
		}
		verifyProof(e, index, val1, proof)
		val2 := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		ne, err := e.BeginModification()
		if err != nil {
			panic(err)
		}
		err = ne.Set(index, val2)
		if err != nil {
			panic(err)
		}
		wb := new(leveldb.Batch)
		flushed := ne.Flush(wb)
		err = db.Write(wb)
		if err != nil {
			panic(err)
		}
		e2 := m.GetSnapshot(flushed.Nr)
		v, p, err := e2.Lookup(index)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(v, val2) {
			panic(fmt.Errorf("Value mismatch: %x / %x", v, val2))
		}
		verifyProof(e2, index, val2, p)
	})
}

func TestTwoEntriesOneEpoch(t *testing.T) {
	withDB(func(db kv.DB) {
		m, err := AccessMerkleTree(db, []byte("abcd"), treeNonce)
		if err != nil {
			panic(err)
		}
		e := m.GetSnapshot(0)
		index := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		val := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		ne, err := e.BeginModification()
		if err != nil {
			panic(err)
		}
		_ = "breakpoint"
		err = ne.Set(index, val)
		if err != nil {
			panic(err)
		}
		// Make sure mutating the slices afterwards is okay
		index[15]++
		val[15]++
		err = ne.Set(index, val)
		if err != nil {
			panic(err)
		}
		wb := new(leveldb.Batch)
		flushed := ne.Flush(wb)
		err = db.Write(wb)
		if err != nil {
			panic(err)
		}
		e2 := m.GetSnapshot(flushed.Nr)
		for i := 0; i < 2; i++ {
			v, p, err := e2.Lookup(index)
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(v, val) {
				panic(fmt.Errorf("Value mismatch: %x vs %x", v, val))
			}
			verifyProof(e2, index, v, p)
			index[15]--
			val[15]--
		}
	})
}

func TestThreeEntriesThreeEpochs(t *testing.T) {
	withDB(func(db kv.DB) {
		m, err := AccessMerkleTree(db, []byte("xyz"), treeNonce)
		if err != nil {
			panic(err)
		}
		indices := [][]byte{
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0},
			[]byte{0xf0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		}
		values := [][]byte{
			[]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			[]byte{3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3},
			[]byte{4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4},
		}
		snapshotNrs := []uint64{0}
		for i := 0; i < len(indices); i++ {
			e := m.GetSnapshot(snapshotNrs[i])
			ne, err := e.BeginModification()
			if err != nil {
				panic(err)
			}
			err = ne.Set(indices[i], values[i])
			if err != nil {
				panic(err)
			}
			wb := new(leveldb.Batch)
			flushed := ne.Flush(wb)
			m, err = AccessMerkleTree(db, []byte("xyz"), treeNonce)
			if err != nil {
				panic(err)
			}
			snapshotNrs = append(snapshotNrs, flushed.Nr)
			err = db.Write(wb)
			if err != nil {
				panic(err)
			}
			for j := 0; j <= i+1; j++ {
				e2 := m.GetSnapshot(snapshotNrs[j])
				for k := 0; k < len(indices); k++ {
					v, p, err := e2.Lookup(indices[k])
					if err != nil {
						panic(err)
					}
					if k < j {
						if !bytes.Equal(v, values[k]) {
							panic(fmt.Errorf("Value mismatch: %x / %x", v, values[k]))
						}
						verifyProof(e2, indices[k], v, p)
					} else {
						if v != nil {
							if !bytes.Equal(v, values[k]) {
								panic(fmt.Errorf("bled value mismatch: %d into %d; %x / %x", i, j, v, values[k]))
							} else {
								panic(fmt.Errorf("epoch bled: %d into %d", i, j))
							}
						}
					}
				}
			}
		}
	})
}

type Map interface {
	GetSnapshot(nr uint64) MapSnapshot
	Refresh() // flush all snapshots first
}

type MapSnapshot interface {
	GetNr() uint64
	Lookup(indexBytes []byte) (value []byte)
	BeginModification() NewMapSnapshot
}

type NewMapSnapshot interface {
	Set(indexBytes, value []byte)
	Flush() MapSnapshot
}

type TestMerkleTree struct {
	tree      *MerkleTree
	db        kv.DB
	prefix    []byte
	treeNonce []byte
}

func makeTestMerkleTree(db kv.DB, prefix, treeNonce []byte) *TestMerkleTree {
	tree := &TestMerkleTree{
		db:        db,
		prefix:    prefix,
		treeNonce: treeNonce,
	}
	tree.Refresh()
	return tree
}

type TestSnapshot Snapshot
type TestNewSnapshot NewSnapshot

var _ Map = (*TestMerkleTree)(nil)
var _ MapSnapshot = (*TestSnapshot)(nil)
var _ NewMapSnapshot = (*TestNewSnapshot)(nil)

func (t *TestMerkleTree) GetSnapshot(nr uint64) MapSnapshot {
	return (*TestSnapshot)(t.tree.GetSnapshot(nr))
}

func (t *TestMerkleTree) Refresh() {
	var err error
	t.tree, err = AccessMerkleTree(t.db, t.prefix, t.treeNonce)
	if err != nil {
		panic(err)
	}
}

func (t *TestSnapshot) GetNr() uint64 {
	return t.Nr
}

func (t *TestSnapshot) Lookup(indexBytes []byte) (value []byte) {
	value, p, err := (*Snapshot)(t).Lookup(indexBytes)
	if err != nil {
		panic(err)
	}
	verifyProof((*Snapshot)(t), indexBytes, value, p)
	return
}

func (t *TestSnapshot) BeginModification() NewMapSnapshot {
	newSnap, err := (*Snapshot)(t).BeginModification()
	if err != nil {
		panic(err)
	}
	return (*TestNewSnapshot)(newSnap)
}

func (t *TestNewSnapshot) Set(indexBytes, value []byte) {
	err := (*NewSnapshot)(t).Set(indexBytes, value)
	if err != nil {
		panic(err)
	}
}

func (t *TestNewSnapshot) Flush() MapSnapshot {
	newSnap := (*NewSnapshot)(t)
	db := newSnap.Snapshot.tree.db
	wb := db.NewBatch()
	flushed := (*TestSnapshot)(newSnap.Flush(wb))
	err := db.Write(wb)
	if err != nil {
		panic(err)
	}
	return flushed
}

type SimpleMap struct {
	snapshots []*SimpleSnapshot
}

type SimpleSnapshot struct {
	nr       uint64
	entries  map[[coname.HashBytes]byte][coname.HashBytes]byte
	wholeMap *SimpleMap
}

type SimpleNewSnapshot struct {
	SimpleSnapshot
}

var _ Map = (*SimpleMap)(nil)
var _ MapSnapshot = (*SimpleSnapshot)(nil)
var _ NewMapSnapshot = (*SimpleNewSnapshot)(nil)

func (m *SimpleMap) GetSnapshot(nr uint64) MapSnapshot {
	if len(m.snapshots) == 0 {
		m.snapshots = append(m.snapshots, &SimpleSnapshot{wholeMap: m, entries: make(map[[coname.HashBytes]byte][coname.HashBytes]byte)})
	}
	return m.snapshots[nr]
}

func (m *SimpleMap) Refresh() {}

func (s *SimpleSnapshot) GetNr() uint64 {
	return s.nr
}

func (s *SimpleSnapshot) Lookup(indexBytes []byte) (value []byte) {
	var bytes [coname.HashBytes]byte
	copy(bytes[:], indexBytes)
	if comm, ok := s.entries[bytes]; ok {
		return comm[:]
	} else {
		return nil
	}
}

func (s *SimpleSnapshot) clone() (cloned *SimpleSnapshot) {
	cloned = &SimpleSnapshot{nr: s.nr, entries: make(map[[coname.HashBytes]byte][coname.HashBytes]byte), wholeMap: s.wholeMap}
	for k, v := range s.entries {
		cloned.entries[k] = v
	}
	return
}

func (s *SimpleSnapshot) BeginModification() NewMapSnapshot {
	return &SimpleNewSnapshot{*s.clone()}
}

func (s *SimpleNewSnapshot) Set(indexBytes, value []byte) {
	var bytes, comm [coname.HashBytes]byte
	copy(bytes[:], indexBytes)
	copy(comm[:], value)
	s.entries[bytes] = comm
}

func (s *SimpleNewSnapshot) Flush() MapSnapshot {
	snap := s.SimpleSnapshot.clone()
	snap.nr = uint64(len(s.wholeMap.snapshots))
	s.wholeMap.snapshots = append(s.wholeMap.snapshots, snap)
	return snap
}

type ComparingMap struct {
	Implementations []Map
	snapshots       [][]uint64
}

type ComparingSnapshot struct {
	Snapshots []MapSnapshot
	nr        uint64
	wholeMap  *ComparingMap
}

type NewComparingSnapshot struct {
	NewSnapshots []NewMapSnapshot
	wholeMap     *ComparingMap
}

var _ Map = (*ComparingMap)(nil)
var _ MapSnapshot = (*ComparingSnapshot)(nil)
var _ NewMapSnapshot = (*NewComparingSnapshot)(nil)

func (m *ComparingMap) GetSnapshot(nr uint64) MapSnapshot {
	if len(m.snapshots) == 0 && nr == 0 {
		nrs := []uint64{}
		for _ = range m.Implementations {
			nrs = append(nrs, 0)
		}
		m.snapshots = append(m.snapshots, nrs)
	}
	nrs := m.snapshots[nr]
	snapshots := []MapSnapshot{}
	for i, impl := range m.Implementations {
		snapshots = append(snapshots, impl.GetSnapshot(nrs[i]))
	}
	return &ComparingSnapshot{snapshots, nr, m}
}

func (m *ComparingMap) Refresh() {
	for _, impl := range m.Implementations {
		impl.Refresh()
	}
}

func (s *ComparingSnapshot) GetNr() uint64 {
	return s.nr
}

func (s *ComparingSnapshot) Lookup(indexBytes []byte) (value []byte) {
	value = s.Snapshots[0].Lookup(indexBytes)
	for _, impl := range s.Snapshots {
		c := impl.Lookup(indexBytes)
		if !bytes.Equal(c, value) {
			log.Panicf("Lookup %x differed: %x vs %x", indexBytes, value, c)
		}
	}
	return
}

func (s *ComparingSnapshot) BeginModification() NewMapSnapshot {
	snapshots := []NewMapSnapshot{}
	for _, impl := range s.Snapshots {
		snapshots = append(snapshots, impl.BeginModification())
	}
	return &NewComparingSnapshot{snapshots, s.wholeMap}
}

func (s *NewComparingSnapshot) Set(indexBytes, value []byte) {
	for _, snap := range s.NewSnapshots {
		snap.Set(indexBytes, value)
	}
}

func (s *NewComparingSnapshot) Flush() MapSnapshot {
	snapshots := []MapSnapshot{}
	nrs := []uint64{}
	for _, newSnap := range s.NewSnapshots {
		flushed := newSnap.Flush()
		snapshots = append(snapshots, flushed)
		nrs = append(nrs, flushed.GetNr())
	}
	s.wholeMap.snapshots = append(s.wholeMap.snapshots, nrs)
	return &ComparingSnapshot{snapshots, uint64(len(s.wholeMap.snapshots) - 1), s.wholeMap}
}

var dbg = 1

func compareImplementationsRandomly(implementations []Map, itCount, byteRange int, t testing.TB) {
	bytez := func(b byte) [coname.HashBytes]byte {
		var bytes [coname.HashBytes]byte
		for i := range bytes {
			bytes[i] = b<<4 | b
		}
		return bytes
	}
	randBytes := func() []byte {
		var bs [coname.HashBytes]byte
		if byteRange < 0 {
			bs = bytez(byte(rand.Intn(-byteRange)))
			bs[0] = byte(rand.Intn(-byteRange))
			bs[coname.HashBytes-1] = byte(rand.Intn(-byteRange))
			return bs[:]
		} else {
			for i := range bs {
				bs[i] = byte(rand.Intn(byteRange))
			}
			return bs[:]
		}
	}
	comparer := ComparingMap{implementations, nil}
	snapshots := []MapSnapshot{comparer.GetSnapshot(0)}
	changingSnapshots := []NewMapSnapshot{}
	existingKeys := [][]byte{}
	// TODO: (for testing) sometimes bias towards long snapshot chains, refresh
	// snapshots, refresh the whole thing (and then all snapshots), check only
	// new snapshots most of the time
	for i := 0; i < itCount; i++ {
		switch op := rand.Intn(3); op {
		case 0:
			// new update
			i := rand.Intn(len(snapshots))
			if dbg > 1 {
				log.Printf("begin %x -> *%x", i, len(changingSnapshots))
			}
			changingSnapshots = append(changingSnapshots, snapshots[i].BeginModification())
		case 1:
			// do changes
			if len(changingSnapshots) > 0 {
				i := rand.Intn(len(changingSnapshots))
				nrSets := rand.Intn(10)
				for j := 0; j < nrSets; j++ {
					var k []byte
					if rand.Intn(3) == 0 && len(existingKeys) > 0 {
						// update existing key
						k = existingKeys[rand.Intn(len(existingKeys))]
					} else {
						// create new key
						k = randBytes()
						existingKeys = append(existingKeys, k)
					}
					v := randBytes()
					if dbg > 1 {
						log.Printf("snap *%x: [%x] <- %x", i, k, v)
					}
					changingSnapshots[i].Set(k, v)
				}
			}
		case 2:
			// finish update
			if len(changingSnapshots) > 0 {
				i := rand.Intn(len(changingSnapshots))
				if dbg > 1 {
					log.Printf("flush *%x -> %x", i, len(snapshots))
				}
				snapshots = append(snapshots, changingSnapshots[i].Flush())
				changingSnapshots = append(changingSnapshots[:i], changingSnapshots[i+1:]...)
			}
		}
		if rand.Intn(50) == 0 {
			// flush everything
			for _, snap := range changingSnapshots {
				snapshots = append(snapshots, snap.Flush())
				changingSnapshots = nil
			}
			comparer.Refresh()
			// reload all the snapshots
			for i := range snapshots {
				snapshots[i] = comparer.GetSnapshot(snapshots[i].GetNr())
			}
		}
		if rand.Intn(10) == 0 {
			// reload random snapshot
			if len(snapshots) > 0 {
				i := rand.Intn(len(snapshots))
				snapshots[i] = comparer.GetSnapshot(snapshots[i].GetNr())
			}
		}
		if i+1 == itCount || (i < 200 && i%10 == 0) {
			// check all consistency
			keysToQuery := existingKeys
			for i := 0; i < 5; i++ {
				keysToQuery = append(keysToQuery, randBytes())
			}
			for _, k := range keysToQuery {
				if dbg > 2 {
					log.Printf("query %x", k)
				}
				for i := range snapshots {
					if dbg > 2 {
						log.Printf("  in %x:", i)
					}
					v := snapshots[i].Lookup(k)
					if dbg > 2 {
						log.Printf("   %x", v)
					}
				}
			}
		}
	}
}

func TestBrutally(t *testing.T) {
	rand.Seed(4)
	if testing.Verbose() {
		dbg = 2
	}
	withDB(func(db kv.DB) {
		m := makeTestMerkleTree(db, []byte("tree1"), treeNonce)
		// Test with randomly distributed keys
		impls := []Map{&SimpleMap{}, m}
		compareImplementationsRandomly(impls, 400, 255, t)
		m2 := makeTestMerkleTree(db, []byte("tree2"), treeNonce)
		// Test with not as random keys
		impls = []Map{&SimpleMap{}, m2}
		compareImplementationsRandomly(impls, 100, -16, t)
	})
}
