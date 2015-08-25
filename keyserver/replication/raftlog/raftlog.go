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

	"google.golang.org/grpc"

	"github.com/andres-erbsen/clock"
	"github.com/coreos/etcd/raft"
	"github.com/coreos/etcd/raft/raftpb"

	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/replication"
	"github.com/yahoo/coname/keyserver/replication/raftlog/proto"
	"golang.org/x/net/context"
)

const (
	HARDSTATE_KEY    = "HS"
	CONFSTATE_KEY    = "CS"
	ENTRY_KEY_PREFIX = "E"
	COMMITTED_BUFFER = 10 // It's fine to let commit run asynchronously ahead of apply
)

type raftLog struct {
	config raft.Config
	node   raft.Node // nil => we are a hot standby and only see committed ents.

	clk          clock.Clock
	tickInterval time.Duration

	waitCommitted chan []byte

	leaderHintSet chan bool
	leaderHint    bool

	grpcServer      *grpc.Server
	dial            func(uint64) proto.RaftClient
	grpcClientCache map[uint64]proto.RaftClient
	grpcDropClient  chan uint64

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}
}

var _ replication.LogReplicator = (*raftLog)(nil)
var _ proto.RaftServer = (*raftLog)(nil)

func (l *raftLog) Step(ctx context.Context, msg *raftpb.Message) (*proto.Nothing, error) {
	return &proto.Nothing{}, l.node.Step(ctx, *msg)
}

// New initializes a replication.LogReplicator using an already open kv.DB and
// registers a raft service with server. It is the caller's responsibility to
// call Serve.
func New(
	thisReplica uint64, initialReplicas []uint64,
	db kv.DB, prefix []byte,
	clk clock.Clock, tickInterval time.Duration,
	server *grpc.Server, dial func(id uint64) proto.RaftClient,
) replication.LogReplicator {
	confState := raftpb.ConfState{}
	for _, id := range initialReplicas {
		confState.Nodes = append(confState.Nodes, id)
	}
	storage := mkRaftStorage(db, prefix, confState)
	l := &raftLog{
		config: raft.Config{
			ID:              thisReplica,
			ElectionTick:    10,
			HeartbeatTick:   1,
			MaxSizePerMsg:   4 * 1024,
			MaxInflightMsgs: 256,
			Storage:         storage,
		},
		node:         nil,
		clk:          clk,
		tickInterval: tickInterval,
		grpcServer:   server,
		dial:         dial,
	}
	proto.RegisterRaftServer(l.grpcServer, l)
	return l
}

// Start implements replication.LogReplicator
func (l *raftLog) Start(lo uint64) error {
	inited, err := l.config.Storage.(*raftStorage).IsInitialized()
	if err != nil {
		return err
	}
	if inited {
		l.config.Applied = lo
		l.node = raft.RestartNode(&l.config)
	} else {
		if lo != 0 {
			log.Panicf("storage uninitialized but state machine not fresh: lo = %d", lo)
		}
		// Add a dummy first entry
		hardState, confState, err := l.config.Storage.InitialState()
		if err != nil {
			return err
		}
		confNodes := make([]raft.Peer, 0, len(confState.Nodes))
		for _, id := range confState.Nodes {
			confNodes = append(confNodes, raft.Peer{ID: id})
		}
		l.config.Storage.(*raftStorage).save(hardState, make([]raftpb.Entry, 1))
		l.node = raft.StartNode(&l.config, confNodes)
	}

	l.leaderHintSet = make(chan bool, COMMITTED_BUFFER)
	l.waitCommitted = make(chan []byte, COMMITTED_BUFFER)
	l.stop = make(chan struct{})
	l.stopped = make(chan struct{})
	l.grpcDropClient = make(chan uint64)
	l.stopOnce = sync.Once{}
	l.grpcClientCache = make(map[uint64]proto.RaftClient)

	go l.run()
	return nil
}

// Stop implements replication.LogReplicator
func (l *raftLog) Stop() error {
	l.stopOnce.Do(func() {
		l.grpcServer.Stop()
		if l.stop != nil {
			close(l.stop)
		}
		if l.stopped != nil {
			<-l.stopped
		}
		if l.node != nil {
			l.node.Stop()
		}
	})
	return nil
}

// Propose implements replication.LogReplicator
func (l *raftLog) Propose(ctx context.Context, data []byte) {
	l.node.Propose(ctx, data)
}

// Propose implements replication.LogReplicator
func (l *raftLog) AddReplica(nodeID uint64) {
	l.node.ApplyConfChange(raftpb.ConfChange{
		Type:   raftpb.ConfChangeAddNode,
		NodeID: nodeID,
	})
}

// Propose implements replication.LogReplicator
func (l *raftLog) DropReplica(nodeID uint64) {
	l.node.ApplyConfChange(raftpb.ConfChange{
		Type:   raftpb.ConfChangeRemoveNode,
		NodeID: nodeID,
	})
	l.grpcDropClient <- nodeID
}

// WaitCommitted implements replication.LogReplicator
func (l *raftLog) WaitCommitted() <-chan []byte {
	return l.waitCommitted
}

// LeaderHintSet implements replication.LogReplicator
func (l *raftLog) LeaderHintSet() <-chan bool {
	return l.leaderHintSet
}

// GetCommitted implements replication.LogReplicator
func (l *raftLog) GetCommitted(lo, hi, maxSize uint64) (ret [][]byte, err error) {
	es, err := l.getCommittedEntries(lo, hi, maxSize)
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		ret = append(ret, entryData(e))
	}
	return ret, err
}

func (l *raftLog) getCommittedEntries(lo, hi, maxSize uint64) ([]raftpb.Entry, error) {
	hs, _, err := l.config.Storage.InitialState()
	if err != nil {
		return nil, err
	}
	entries, err := l.config.Storage.(*raftStorage).Entries(lo, hi, maxSize)
	if err != nil {
		return nil, err
	}
	i := 0
	for i < len(entries) && entries[i].Index <= hs.Commit {
		i++
	}
	return entries[:i], nil
}

func entryData(e raftpb.Entry) []byte {
	if e.Type == raftpb.EntryNormal {
		return e.Data
	}
	return nil
}

// run is the CSP-style main of raftLog; all local struct fields (except
// channels) belong exclusively to run while it is running. Method invocations
// are signaled through channels.
func (l *raftLog) run() {
	defer close(l.waitCommitted)
	defer close(l.stopped)
	defer close(l.leaderHintSet)
	ticker := l.clk.Ticker(l.tickInterval)
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.node.Tick()
		case r := <-l.grpcDropClient:
			delete(l.grpcClientCache, r)
		case rd := <-l.node.Ready():
			if !raft.IsEmptySnap(rd.Snapshot) {
				log.Panicf("snapshots not supported")
			}
			l.config.Storage.(*raftStorage).save(rd.HardState, rd.Entries)
			for i := range rd.Messages {
				l.send(&rd.Messages[i])
			}
			for _, entry := range rd.CommittedEntries {
				select {
				case l.waitCommitted <- entryData(entry):
				case <-l.stop:
					return
				}
			}

			if rd.SoftState != nil {
				leaderHint := rd.SoftState.RaftState == raft.StateLeader
				if l.leaderHint != leaderHint {
					l.leaderHint = leaderHint
					select {
					case l.leaderHintSet <- leaderHint:
					default:
					}
				}
			}
			l.node.Advance()
		}
	}
}

// send synchronouslt accesses l.grpcConnectionCache and then asynchronously
// sends msg to msg.To, reporting an error if necessary.
func (l *raftLog) send(msg *raftpb.Message) {
	c, ok := l.grpcClientCache[msg.To]
	if !ok {
		c = l.dial(msg.To)
		l.grpcClientCache[msg.To] = c
	}
	go func(msg raftpb.Message) {
		ctx, _ := context.WithTimeout(context.Background(), 10*l.tickInterval)
		_, err := c.Step(ctx, &msg)
		if err != nil {
			log.Printf("raftlog send to %x: %s", msg.To, err)
			l.node.ReportUnreachable(msg.To)
		}
	}(*msg)
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

func mkRaftStorage(db kv.DB, prefix []byte, initialConf raftpb.ConfState) *raftStorage {
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
