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
	"sync"

	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/replication"
	"golang.org/x/net/context"
)

// kvLog implements replication.LogReplicator using a NOT NECESSARILY
// REPLICATED persistent key-value database.
type kvLog struct {
	db         kv.DB
	prefix     []byte
	nextIndex  uint64
	skipBefore uint64

	leaderHintSet chan bool
	propose       chan replication.LogEntry
	waitCommitted chan replication.LogEntry

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}
}

var _ replication.LogReplicator = (*kvLog)(nil)

// New initializes a replication.LogReplicator using an already open kv.DB.
func New(db kv.DB, prefix []byte) (replication.LogReplicator, error) {
	nextIndex := uint64(0)
	iter := db.NewIterator(kv.BytesPrefix(prefix))
	if hasEntries := iter.Last(); hasEntries {
		nextIndex = binary.BigEndian.Uint64(iter.Key()[len(prefix):]) + 1
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, err
	}

	leaderHintSet := make(chan bool, 1)
	leaderHintSet <- true
	return &kvLog{
		db:            db,
		prefix:        prefix,
		nextIndex:     nextIndex,
		propose:       make(chan replication.LogEntry, 100),
		leaderHintSet: leaderHintSet,
		waitCommitted: make(chan replication.LogEntry),
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}, nil
}

// Start implements replication.LogReplicator
func (l *kvLog) Start(lo uint64) error {
	l.skipBefore = lo
	go l.run()
	return nil
}

// Stop implements replication.LogReplicator
func (l *kvLog) Stop() error {
	l.stopOnce.Do(func() {
		close(l.stop)
		<-l.stopped
	})
	return nil
}

// ApplyConfChange implements replication.LogReplicator
func (l *kvLog) ApplyConfChange(*replication.ConfChange) {
	panic("ApplyConfChange: cannot reconfigure kvlog")
}

// Propose implements replication.LogReplicator
// The following is true for kvLog.Propose but not necessarilty for other
// implementations of replication.LogReplicator: If Propose(x) returns, then
// after some amount of time without crashes, WaitCommitted returns x.
func (l *kvLog) Propose(ctx context.Context, en replication.LogEntry) {
	if en.ConfChange != nil && en.ConfChange.Operation != replication.ConfChangeNOP {
		panic("Propose: cannot reconfigure kvlog")
	}
	select {
	case l.propose <- replication.LogEntry{Data: en.Data}:
	case <-l.stop:
	}
}

// WaitCommitted implements replication.LogReplicator
func (l *kvLog) WaitCommitted() <-chan replication.LogEntry {
	return l.waitCommitted
}

// WaitCommitted implements replication.LogReplicator
func (l *kvLog) LeaderHintSet() <-chan bool {
	return l.leaderHintSet
}

// GetCommitted implements replication.LogReplicator
func (l *kvLog) GetCommitted(lo, hi, maxSize uint64) (ret []replication.LogEntry, err error) {
	size := uint64(0)
	for i := lo; i < hi; i++ {
		var v replication.LogEntry
		v, err = l.get(i)
		if err != nil {
			if err == l.db.ErrNotFound() {
				return ret, nil
			}
			return nil, err
		}
		if len(ret) != 0 && size+uint64(len(v.Data)) > maxSize {
			return
		}
		ret = append(ret, v)
		size += uint64(len(v.Data))
		if size >= maxSize {
			return
		}
	}
	return
}

// get returns entry number i from l.db
func (l *kvLog) get(i uint64) (le replication.LogEntry, err error) {
	dbkey := make([]byte, len(l.prefix)+8)
	copy(dbkey, l.prefix)
	binary.BigEndian.PutUint64(dbkey[len(l.prefix):], i)
	entryBytes, err := l.db.Get(dbkey[:])
	if err != nil {
		return le, err
	}
	return replication.LogEntry{Data: entryBytes}, nil
}

// run is the CSP-style main of kvLog, all local struct fields (except
// channels) belong exclusively to run while it is running. Method invocations
// are signaled through channels.
func (l *kvLog) run() {
	defer close(l.stopped)
	defer close(l.waitCommitted)
	for i := l.skipBefore; i < l.nextIndex; i++ {
		v, err := l.get(i)
		if err != nil {
			panic(err)
		}
		select {
		case <-l.stop:
			return
		case l.waitCommitted <- v:
		}
	}
	dbkey := make([]byte, len(l.prefix)+8)
	copy(dbkey, l.prefix)
	for {
		select {
		case <-l.stop:
			return
		case prop := <-l.propose:
			binary.BigEndian.PutUint64(dbkey[len(l.prefix):], l.nextIndex)
			l.nextIndex++
			l.db.Put(dbkey[:], prop.Data)
			select {
			case <-l.stop:
				return
			case l.waitCommitted <- prop:
			}
		}
	}
}
