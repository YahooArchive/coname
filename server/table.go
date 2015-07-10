package server

import "encoding/binary"

var (
	tableReplicationLogPrefix byte = 'l' // index uint64 -> []byte
	tableRatificationsPrefix  byte = 'r' // epoch uint64, ratifier uint64 -> proto.SignedRatification

	tableReplicaState = []byte{'e'} // proto.ReplicaState
)

func tableRatifications(epoch, ratifier uint64) []byte {
	ret := make([]byte, 1+8+8)
	ret[0] = tableRatificationsPrefix
	binary.BigEndian.PutUint64(ret[1:1+8], epoch)
	binary.BigEndian.PutUint64(ret[1+8:1+8+8], ratifier)
	return ret
}
