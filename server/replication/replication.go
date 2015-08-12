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

package replication

import (
	"golang.org/x/net/context"
)

// LogReplicator is a generic interface to state-machine replication logs.  The
// log is a mapping from uint64 slot indices to []byte entries in which all
// entries that have been committed are reliably persistent even throughout
// machine crashes and data losses at a limited number of replicas. This is
// achieved by trading off availability: proposing a new entry does not
// necessarily mean it will be committed. One would use this interface
// similarly to a local write-ahead log, except that this interface does not
// support log compaction (it is intended for use when the entire log needs to
// be kept around anyway). Returned nil entries should be ignored.
// Start(lo) must be called exactly once before any other method is called, and
// no methods must be called after Stop is called. The other three methods may
// be called concurrently.
type LogReplicator interface {
	// Start sets an internal field lo; later WaitCommitted will return entries
	// with indices >= lo. Start must be called before any other methods are.
	Start(lo uint64) error

	// Propose moves to append data to the log. It is not guaranteed that the
	// entry will get appended, though, due to node or network failures.
	// data : []*mut // ownership of the slice contents is transferred to LogReplicator
	Propose(ctx context.Context, data []byte)

	// WaitCommitted returns a channel that returns new committed entries,
	// starting with the index passed to Start.
	// All calls return the same channel.
	// ch : chan (&[]byte) // all read values are read-only to the caller
	WaitCommitted() <-chan []byte

	// Stop cleanly stops logging requests. No calls to Propose must be started
	// after Stop has been called (and the values handed to ongoing Propose
	// calls may not get committed). WaitCommitted and LeaderHintSet channels
	// are closed.
	Stop() error

	// AddReplica adds nodeID to the set of replicas THIS REPLICA considers a
	// part of the cluster. The decision to call AddReplica MUST be purely
	// based on the contents of the log, and MUST be the same at all replicas.
	// In particular, not allowed to add or drop a replica based on its
	// observed health (unless, of course, the data about the health is in the
	// log). Adding a replica to a non-redundant cluster (e.g., two nodes, or
	// alternatively, three nodes with one of them being dead) will block
	// progress until the new replica has caught up.
	AddReplica(nodeID uint64)
	DropReplica(nodeID uint64)

	// LeaderHintSet returns a channel that reads true when it becomes likely
	// this replica is the leader of the cluster, and false when it is no onger
	// likely. Users MUST NOT rely on this for correctness. For example, it is
	// totally possible for two replicas have leaderHint=true at the same time.
	LeaderHintSet() <-chan bool

	// GetCommitted loads committed entries for post-replication distribution:
	// 1. The first returned entry corresponds to Index = lo
	// 2. All returned entries are consecutive
	// 3. No entry with Index >= hi is returned
	// 4. At least one entry is returned, if there is any.
	// 5. After that, no more than maxSize total bytes are returned (the first
	//    entry counts towards the max size but is always returned)
	// ret: []&[]byte // All returned byte slices are read-only for the caller.
	GetCommitted(lo, hi, maxSize uint64) ([][]byte, error)
}
