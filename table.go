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

package coname

import (
	"encoding/binary"

	"github.com/yahoo/coname/vrf"
)

// NOTE: All uint64 keys are big-endian encoded to make lexicographical order
// correspond to numeric order.
var (
	TableReplicationLogPrefix             byte = 'l' // index uint64 -> proto.KeyserverStep
	TableVerifierLogPrefix                byte = 'v' // index uint64 -> proto.VerifierStep
	TableRatificationsPrefix              byte = 'r' // epoch uint64, ratifier uint64 -> []byte (signature)
	TableEpochHeadsPrefix                 byte = 'e' // epoch uint64 -> proto.TimestampedEpochHead
	TableUpdateRequestsPrefix             byte = 'u' // vrfidx [vrf.Size]byte -> epoch uint64 -> proto.UpdateRequest
	TableMerkleTreePrefix                 byte = 't'
	TableUpdatesPendingRatificationPrefix byte = 'p' // logIndex uint64 -> proto.SignedEntryUpdate

	TableEntriesPrefix       byte = 'e' // vrfidx [vrf.Size]byte -> epoch uint64 -> proto.Entry

	TableEpochDelimiterPrefix byte = 'd'
	TablePendingUpdateRequestsPrefix byte = 'w'

	TableMerkleTreeSnapshotPrefix         byte = 'm' // epochNumber uint64 -> snapshotNumber uint64

	TableReplicaState = []byte{'s'} // proto.ReplicaState
)

func TableRatifications(epoch, ratifier uint64) []byte {
	ret := make([]byte, 1+8+8)
	ret[0] = TableRatificationsPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	binary.BigEndian.PutUint64(ret[1+8:1+8+8], ratifier)
	return ret
}

func TableEpochHeads(epoch uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = TableEpochHeadsPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	return ret
}

func TableVerifierLog(index uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = TableVerifierLogPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], index)
	return ret
}

func TableUpdateRequests(vrfidx []byte, epoch uint64) []byte {
	ret := make([]byte, 1+vrf.Size+8)
	ret[0] = TableUpdateRequestsPrefix
	copy(ret[1:1+vrf.Size], vrfidx)
	binary.BigEndian.PutUint64(ret[1+vrf.Size:1+vrf.Size+8], epoch)
	return ret
}

func TablePendingUpdateRequests(vrfidx []byte, epoch uint64) []byte {
	ret := make([]byte, 1+vrf.Size+8)
	ret[0] = TablePendingUpdateRequestsPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	copy(ret[1+8:1+8+vrf.Size], vrfidx)
	return ret
}

func TableUpdatesPendingRatification(logIndex uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = TableUpdatesPendingRatificationPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], logIndex)
	return ret
}


func TableEntries(vrfidx []byte, epoch uint64) []byte {
	ret := make([]byte, 1+vrf.Size+8)
	ret[0] = TableEntriesPrefix
	copy(ret[1:1+vrf.Size], vrfidx)
	binary.BigEndian.PutUint64(ret[1+vrf.Size:1+vrf.Size+8], epoch)
	return ret
}

func TableEpochDelimiter(epoch uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = TableEpochDelimiterPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	return ret
}
