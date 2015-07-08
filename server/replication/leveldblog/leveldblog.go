package leveldblog

import (
	"encoding/binary"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/net/context"
	"github.com/yahoo/coname/server/replication"
)

// leveldbLog implements replication.LogReplicator using a NON-REPLICATED but
// persistent levelDB database.
type leveldbLog struct {
	db         *leveldb.DB
	nextIndex  uint64
	skipBefore uint64

	propose       chan []byte
	waitCommitted chan []byte
	close         chan struct{}
	closed        chan struct{}
}

var _ replication.LogReplicator = (*leveldbLog)(nil)

// NewLeveldbLog initializes a replication.LogReplicator using an already open
// leveldb instance.
func NewLeveldbLog(db *leveldb.DB) (replication.LogReplicator, error) {
	nextIndex := uint64(0)
	iter := db.NewIterator(util.BytesPrefix(nil), nil)
	if hasEntries := iter.Last(); hasEntries {
		nextIndex = binary.BigEndian.Uint64(iter.Key()) + 1
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, err
	}

	return &leveldbLog{
		db:            db,
		nextIndex:     nextIndex,
		propose:       make(chan []byte, 100),
		waitCommitted: make(chan []byte),
		close:         make(chan struct{}),
		closed:        make(chan struct{}),
	}, nil
}

// Start implements replication.LogReplicator
func (l *leveldbLog) Start(lo uint64) error {
	l.skipBefore = lo
	go l.run()
	return nil
}

// Close implements replication.LogReplicator
func (l *leveldbLog) Close() error {
	select {
	case <-l.close:
		return nil // already closing
	default:
	}
	close(l.close)
	<-l.closed
	return nil
}

// Propose implements replication.LogReplicator
// The following is true for leveldbLog.Propose but not necessarilty for other
// implementations of replication.LogReplicator: If Propose(x) returns, then
// after some amount of time without crashes, WaitCommitted returns x.
func (l *leveldbLog) Propose(ctx context.Context, data []byte) {
	select {
	case l.propose <- data:
	case <-l.close:
	}
}

// WaitCommitted implements replication.LogReplicator
func (l *leveldbLog) WaitCommitted() <-chan []byte {
	return l.waitCommitted
}

// GetCommitted implements replication.LogReplicator
func (l *leveldbLog) GetCommitted(lo, hi, maxSize uint64) (ret [][]byte, err error) {
	size := uint64(0)
	for i := lo; i < hi; i++ {
		var v []byte
		v, err = l.get(i)
		if err != nil {
			if err == errors.ErrNotFound {
				return ret, nil
			}
			return nil, err
		}
		if len(ret) != 0 && size+uint64(len(v)) > maxSize {
			return
		}
		ret = append(ret, v)
		size += uint64(len(v))
		if size >= maxSize {
			return
		}
	}
	return
}

// get returns entry number i from l.db
func (l *leveldbLog) get(i uint64) ([]byte, error) {
	var dbkey [8]byte
	binary.BigEndian.PutUint64(dbkey[:], i)
	return l.db.Get(dbkey[:], nil)
}

// run is the CSP-style main of leveldbLog, all local struct fields (except
// channels) belong exclusively to run while it is running. Method invocations
// are signaled through channels.
func (l *leveldbLog) run() {
	defer close(l.closed)
	defer close(l.waitCommitted)
	for i := l.skipBefore; i < l.nextIndex; i++ {
		v, err := l.get(i)
		if err != nil {
			panic(err)
		}
		select {
		case <-l.close:
			return
		case l.waitCommitted <- v:
		}
	}
	for {
		select {
		case <-l.close:
			return
		case prop := <-l.propose:
			var dbkey [8]byte
			binary.BigEndian.PutUint64(dbkey[:], l.nextIndex)
			l.nextIndex++
			l.db.Put(dbkey[:], prop, &opt.WriteOptions{Sync: true})
			select {
			case <-l.close:
				return
			case l.waitCommitted <- prop:
			}
		}
	}
}
