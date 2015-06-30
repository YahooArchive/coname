package leveldblog

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"

	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb"
)

func TestLeveldbLog(t *testing.T) {
	dir, err := ioutil.TempDir("", "leveldblog")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	l := NewLeveldbLog(db)
	l.Start(0)

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

	l.Close()
	l = NewLeveldbLog(db)
	l.Start(3)
	defer l.Close()

	state = uint64(0)
	for i := 0; i < 12; i++ {
		entry := <-l.WaitCommitted()
		e := binary.BigEndian.Uint64(entry)
		if e > 15 {
			t.Errorf("%d (which is > 15) received from WaitCommitted", e)
		}
		state <<= 4
		state |= e
	}

	ref = uint64(0x456789abcdef)
	if state != ref {
		t.Errorf("expected %x\n"+
			"got      %x\n", ref, state)
	}

	entries, err := l.GetCommitted(1, 14, 1<<63)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 13 {
		t.Errorf("GetCommitted: asked for 13 entries, got %d", len(entries))
	}
	for i := uint64(0); i < 13; i++ {
		ref := make([]byte, 8)
		binary.BigEndian.PutUint64(ref, i+2)
		if !bytes.Equal(entries[i], ref) {
			t.Errorf("entries[%d]: expected %x, got %x", i, ref, entries[i])
		}
	}

	entriesLimited, err := l.GetCommitted(3, 14, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesLimited) != 2 {
		s := 0
		for _, e := range entriesLimited {
			s += len(e)
		}
		t.Errorf("CommittedEntries asked for 16 bytes, got %d", s)
	}
}
