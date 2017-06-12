package merkletree

import (
	"fmt"
	"encoding/binary"

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/keyserver/kv"
)

func tableMerkleTreeSnapshot(epoch uint64) []byte {
	ret := make([]byte, 1+8)
	ret[0] = coname.TableMerkleTreeSnapshotPrefix
	binary.BigEndian.PutUint64(ret[1:], epoch)
	return ret
}

func (tree *MerkleTree) MerkletreeForEpoch(epoch uint64) (*Snapshot, error) {
	if epoch == 0 {
		// Special-case epoch 0: It is always empty
		return tree.GetSnapshot(0), nil
	}
	snapshotNrBytes, err := tree.db.Get(tableMerkleTreeSnapshot(epoch))
	if err != nil {
		return nil, err
	}
	if len(snapshotNrBytes) != 8 {
		return nil, fmt.Errorf("bad snapshot number for epoch %d: %x", epoch, snapshotNrBytes)
	}
	snapshotNr := binary.BigEndian.Uint64(snapshotNrBytes)
	return tree.GetSnapshot(snapshotNr), nil
}

func (tree *MerkleTree) SaveSnapshotWithEpoch(epoch uint64, snapshot uint64, wb kv.Batch) {
	snapshotNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(snapshotNumberBytes, snapshot)
	wb.Put(tableMerkleTreeSnapshot(epoch), snapshotNumberBytes)
}

func (tree *MerkleTree) GetLatestSnapshot() (epoch uint64, snapshot uint64) {
	iter := tree.db.NewIterator(&kv.Range{
		Start: tableMerkleTreeSnapshot(0),
		Limit: kv.IncrementKey([]byte{coname.TableMerkleTreeSnapshotPrefix}),
	})
	if iter.Last() {
		epoch = binary.BigEndian.Uint64(iter.Key()[1:])
		snapshot = binary.BigEndian.Uint64(iter.Value())
		return
	} else {
		return 0, 0
	}
}
