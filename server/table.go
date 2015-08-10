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

package server

import (
	"encoding/binary"

	"github.com/yahoo/coname/common/vrf"
)

var (
	tableReplicationLogPrefix     byte = 'l' // index uint64 -> proto.KeyserverStep // TODO: multiple steps per replication log entry
	tableVerifierLogPrefix        byte = 'v' // index uint64 -> proto.VerifierStep
	tableRatificationsPrefix      byte = 'r' // epoch uint64, ratifier uint64 -> proto.SignedEpochHead
	tableUpdateRequestsPrefix     byte = 'u' // vrfidx [vrf.Size]byte -> epoch uint64 -> proto.SignedEpochHead
	tableMerkleTreeSnapshotPrefix byte = 's' // epochNumber uint64 -> snapshotNumber uint64
	tableMerkleTreePrefix         byte = 't'

	tableReplicaState = []byte{'e'} // proto.ReplicaState
)

func tableRatifications(epoch, ratifier uint64) []byte {
	ret := make([]byte, 1+8+8)
	ret[0] = tableRatificationsPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	binary.BigEndian.PutUint64(ret[1+8:1+8+8], ratifier)
	return ret
}

func tableVerifierLog(index uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = tableVerifierLogPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], index)
	return ret
}

func tableUpdateRequests(vrfidx []byte, epoch uint64) []byte {
	ret := make([]byte, 1+vrf.Size+8)
	ret[0] = tableUpdateRequestsPrefix
	copy(ret[1:1+vrf.Size], vrfidx)
	binary.BigEndian.PutUint64(ret[1+vrf.Size:1+vrf.Size+8], epoch)
	return ret
}

func tableMerkleTreeSnapshot(epoch uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = tableMerkleTreeSnapshotPrefix
	binary.BigEndian.PutUint64(ret[1:], epoch)
	return ret
}
