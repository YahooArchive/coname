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

package kvlog

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/keyserver/replication"
)

func setupLevelDB(t *testing.T) (*leveldb.DB, func()) {
	dir, err := ioutil.TempDir("", "leveldblog")
	if err != nil {
		t.Fatal(err)
	}
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	return db, func() {
		db.Close()
		os.RemoveAll(dir)
	}
}

var prefix15 = []byte{'l'}

func setupLog1through15Start(t *testing.T) (replication.LogReplicator, kv.DB, func()) {
	ldb, teardown := setupLevelDB(t)
	db := leveldbkv.Wrap(ldb)

	l, err := New(db, prefix15)
	if err != nil {
		teardown()
		t.Fatal(err)
	}

	l.Start(0)
	for i := uint64(1); i < 16; i++ {
		prop := make([]byte, 8)
		binary.BigEndian.PutUint64(prop, i)
		l.Propose(nil, prop)
		<-l.WaitCommitted()
	}
	return l, db, func() {
		l.Stop()
		teardown()
	}
}

// TestLeveldbLogProposeWait verifies that all Proposed values are returned by
// WaitCommitted. This is not required to be true by the interface, but it is
// true for kvLog and the tests in this module assume that.
func TestLeveldbLogProposeWait(t *testing.T) {
	db, teardown := setupLevelDB(t)
	defer teardown()
	l, err := New(leveldbkv.Wrap(db), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	l.Start(0)
	defer l.Stop()

	for i := uint64(1); i < 16; i++ {
		prop := make([]byte, 8)
		binary.BigEndian.PutUint64(prop, i)
		l.Propose(nil, prop)
	}

	state := uint64(0)
	for i := 1; i < 16; i++ {
		entry := <-l.WaitCommitted()
		e := binary.BigEndian.Uint64(entry)
		if e > 15 {
			t.Errorf("%d (which is > 15) received from WaitCommitted", e)
		}
		state <<= 4
		state |= e
	}

	ref := uint64(0x123456789abcdef)
	if state != ref {
		t.Errorf("expected %x\n"+
			"got      %x\n", ref, state)
	}
}

// TestLeveldbLogStartHistoric verifies that entries already returned by
// GetCommitted and then re-requested after using Start are returned by both
// the following WaitCommitted.
func TestLeveldbLogStartHistoric(t *testing.T) {
	l, db, teardown := setupLog1through15Start(t)
	defer teardown()
	l.Stop()

	l, err := New(db, prefix15)
	if err != nil {
		t.Fatal(err)
	}

	l.Start(3)

	state := uint64(0)
	for i := 0; i < 12; i++ {
		entry := <-l.WaitCommitted()
		e := binary.BigEndian.Uint64(entry)
		if e > 15 {
			t.Errorf("%d (which is > 15) received from WaitCommitted", e)
		}
		state <<= 4
		state |= e
	}

	ref := uint64(0x456789abcdef)
	if state != ref {
		t.Errorf("expected %x\n"+
			"got      %x\n", ref, state)
	}
}
