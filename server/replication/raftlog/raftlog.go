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

package raftlog

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/coreos/etcd/raft"
	"github.com/coreos/etcd/raft/raftpb"

	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/replication"
	"golang.org/x/net/context"
)

const (
	HARDSTATE_KEY    = "HS"
	CONFSTATE_KEY    = "CS"
	ENTRY_KEY_PREFIX = "E"
	COMMITTED_BUFFER = 10 // It's fine to let commit run asynchronously ahead of apply
)

type raftLog struct {
	config       raft.Config
	initialNodes []raft.Peer
	storage      *raftStorage
	node         raft.Node

	clk          clock.Clock
	tickInterval time.Duration

	waitCommitted chan replication.LogEntry

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}
}

var _ replication.LogReplicator = (*raftLog)(nil)

// New initializes a replication.LogReplicator using an already open kv.DB.
// TODO: config.Applied and config.Storage are useless for the caller, and
// initialNodes and tickInterval are included; may want our own config struct
func New(
	db kv.DB, prefix []byte, config *raft.Config, initialNodes []raft.Peer,
	clk clock.Clock, tickInterval time.Duration,
) (replication.LogReplicator, error) {
	confState := raftpb.ConfState{}
	for _, node := range initialNodes {
		confState.Nodes = append(confState.Nodes, node.ID)
	}
	return &raftLog{
		config:        *config,
		initialNodes:  initialNodes,
		storage:       openRaftStorage(db, prefix, confState),
		node:          nil,
		clk:           clk,
		tickInterval:  tickInterval,
		waitCommitted: make(chan replication.LogEntry, COMMITTED_BUFFER),
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}, nil
}

// Start implements replication.LogReplicator
func (l *raftLog) Start(lo uint64) error {
	l.config.Storage = l.storage
	inited, err := l.storage.IsInitialized()
	if err != nil {
		return err
	}
	if inited {
		l.config.Applied = lo
		l.node = raft.RestartNode(&l.config)
	} else {
		if lo != 0 {
			panic(fmt.Errorf("storage uninitialized but state machine not fresh: lo = %d", lo))
		}
		l.node = raft.StartNode(&l.config, l.initialNodes)
	}
	go l.run()
	return nil
}

// Stop implements replication.LogReplicator
func (l *raftLog) Stop() error {
	l.stopOnce.Do(func() {
		close(l.stop)
		<-l.stopped
	})
	return nil
}

// Propose implements replication.LogReplicator
func (l *raftLog) Propose(ctx context.Context, data []byte) {
	l.node.Propose(ctx, data)
}

// Propose implements replication.LogReplicator
func (l *raftLog) ProposeConfChange(ctx context.Context, change []byte) {
	panic("raftLog.ProposeConfChange not implemented")
}

// WaitCommitted implements replication.LogReplicator
func (l *raftLog) WaitCommitted() <-chan replication.LogEntry {
	return l.waitCommitted
}

// GetCommitted implements replication.LogReplicator
func (l *raftLog) GetCommitted(lo, hi, maxSize uint64) (ret []replication.LogEntry, err error) {
	var entries []raftpb.Entry
	entries, err = l.storage.Entries(lo, hi, maxSize)
	if err != nil {
		return
	}
	for _, entry := range entries {
		ret = append(ret, replication.LogEntry{Data: entry.Data})
	}
	return
}

// run is the CSP-style main of raftLog; all local struct fields (except
// channels) belong exclusively to run while it is running. Method invocations
// are signaled through channels.
func (l *raftLog) run() {
	defer close(l.waitCommitted)
	defer close(l.stopped)
	ticker := l.clk.Ticker(l.tickInterval)
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.node.Tick()
		case rd := <-l.node.Ready():
			if !raft.IsEmptySnap(rd.Snapshot) {
				log.Panicf("snapshots not supported")
			}
			l.storage.save(rd.HardState, rd.Entries)
			// TODO send(rd.Messages)
			for _, entry := range rd.CommittedEntries {
				switch entry.Type {
				case raftpb.EntryConfChange:
					var cc raftpb.ConfChange
					cc.Unmarshal(entry.Data)
					l.node.ApplyConfChange(cc)
					l.waitCommitted <- replication.LogEntry{Reconfiguration: entry.Data}
				default:
					l.waitCommitted <- replication.LogEntry{Data: entry.Data}
				}
				l.node.Advance() // let Raft proceed
			}
		}
	}
}

// Needs to be threadsafe; right now, carries no in-memory mutable state
type raftStorage struct {
	hardStateKey   []byte
	confStateKey   []byte
	entryKeyPrefix []byte
	db             kv.DB
	initialConf    raftpb.ConfState
}

var _ raft.Storage = (*raftStorage)(nil)

func openRaftStorage(db kv.DB, prefix []byte, initialConf raftpb.ConfState) *raftStorage {
	return &raftStorage{
		hardStateKey:   append(append([]byte{}, prefix...), HARDSTATE_KEY...),
		confStateKey:   append(append([]byte{}, prefix...), CONFSTATE_KEY...),
		entryKeyPrefix: append(append([]byte{}, prefix...), ENTRY_KEY_PREFIX...),
		db:             db,
		initialConf:    initialConf,
	}
}

// Returns whether an existing state has been persisted to the storage
func (s *raftStorage) IsInitialized() (bool, error) {
	switch _, err := s.db.Get(s.hardStateKey); err {
	case s.db.ErrNotFound():
		return false, nil
	case nil:
		return true, nil
	default:
		return false, err
	}
}

// InitialState implements the raft.Storage interface
func (s *raftStorage) InitialState() (hardState raftpb.HardState, confState raftpb.ConfState, err error) {
	// Restore the confState if we can, otherwise use s.initialConf
	var confStateBytes []byte
	confStateBytes, err = s.db.Get(s.confStateKey)
	if err == s.db.ErrNotFound() {
		confState = s.initialConf
	} else if err != nil {
		return
	}
	err = confState.Unmarshal(confStateBytes)
	if err != nil {
		return
	}
	var hardStateBytes []byte
	hardStateBytes, err = s.db.Get(s.hardStateKey)
	if err == s.db.ErrNotFound() {
		err = nil
		return
	} else if err != nil {
		return
	}
	err = hardState.Unmarshal(hardStateBytes)
	if err != nil {
		return
	}
	return
}

func (s *raftStorage) getEntryKey(nr uint64) (key []byte) {
	key = make([]byte, len(s.entryKeyPrefix)+8)
	copy(key, s.entryKeyPrefix)
	binary.BigEndian.PutUint64(key[len(s.entryKeyPrefix):], nr)
	return
}

// Entries implements the raft.Storage interface
func (s *raftStorage) Entries(lo, hi, maxSize uint64) (entries []raftpb.Entry, err error) {
	it := s.db.NewIterator(&kv.Range{s.getEntryKey(lo), s.getEntryKey(hi)})
	defer it.Release()
	entries = make([]raftpb.Entry, 0)
	sizeSoFar := uint64(0)
	for ok := it.First(); ok; ok = it.Next() {
		var entry raftpb.Entry
		err = entry.Unmarshal(it.Value())
		if err != nil {
			return
		}
		sizeSoFar += uint64(entry.Size())
		// Only stop if we already have at least one entry
		if sizeSoFar > maxSize && len(entries) > 0 {
			break
		}
		entries = append(entries, entry)
		if sizeSoFar >= maxSize {
			break
		}
	}
	err = it.Error()
	return
}

// Term implements the raft.Storage interface
func (s *raftStorage) Term(i uint64) (uint64, error) {
	entries, err := s.Entries(i, i+1, math.MaxUint64)
	if err != nil {
		return 0, err
	}
	if len(entries) != 1 {
		log.Panicf("number of entries with index %d not 1: %d", i, len(entries))
	}
	return entries[0].Term, nil
}

// LastIndex implements the raft.Storage interface
func (s *raftStorage) LastIndex() (uint64, error) {
	it := s.db.NewIterator(kv.BytesPrefix(s.entryKeyPrefix))
	defer it.Release()
	if !it.Last() {
		return 0, it.Error()
	}
	indexPortion := it.Key()[len(s.entryKeyPrefix):]
	return binary.BigEndian.Uint64(indexPortion), it.Error()
}

// FirstIndex implements the raft.Storage interface
func (s *raftStorage) FirstIndex() (uint64, error) {
	// Start at index 1 to be consistent with etcd/raft's MemoryStorage
	// (not sure if this is actually necessary)
	return 1, nil
}

// Snapshot implements the raft.Storage interface
func (s *raftStorage) Snapshot() (raftpb.Snapshot, error) {
	return raftpb.Snapshot{}, nil
}

// Don't call this multiple times concurrently
func (s *raftStorage) save(state raftpb.HardState, entries []raftpb.Entry) error {
	wb := s.db.NewBatch()
	stateBytes, err := state.Marshal()
	if err != nil {
		return err
	}
	wb.Put(s.hardStateKey, stateBytes)
	if len(entries) > 0 {
		lastIndex, err := s.LastIndex()
		if err != nil {
			return err
		}
		if entries[0].Index > lastIndex+1 {
			panic(fmt.Errorf("missing log entries [last: %d, append at: %d]", lastIndex, entries[0].Index))
		}
		// clear all old entries past the new index, if any
		for ix := entries[0].Index; ix <= lastIndex; ix++ {
			wb.Delete(s.getEntryKey(ix))
		}
		// append the new entries
		for _, entry := range entries {
			entryBytes, err := entry.Marshal()
			if err != nil {
				return err
			}
			wb.Put(s.getEntryKey(entry.Index), entryBytes)
		}
	}
	err = s.db.Write(wb)
	return err
}
