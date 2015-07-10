package kvlog

import (
	"encoding/binary"
	"sync"

	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/replication"
	"golang.org/x/net/context"
)

// kvLog implements replication.LogReplicator using a NOT NECESSARILY
// REPLICATED persistent key-value database.
type kvLog struct {
	db         kv.DB
	prefix     []byte
	nextIndex  uint64
	skipBefore uint64

	propose       chan []byte
	waitCommitted chan []byte

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}
}

var _ replication.LogReplicator = (*kvLog)(nil)

// NewLeveldbLog initializes a replication.LogReplicator using an already open
// leveldb instance.
func NewLeveldbLog(db kv.DB, prefix []byte) (replication.LogReplicator, error) {
	nextIndex := uint64(0)
	iter := db.NewIterator(kv.BytesPrefix(prefix))
	if hasEntries := iter.Last(); hasEntries {
		nextIndex = binary.BigEndian.Uint64(iter.Key()[len(prefix):]) + 1
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, err
	}

	return &kvLog{
		db:            db,
		prefix:        prefix,
		nextIndex:     nextIndex,
		propose:       make(chan []byte, 100),
		waitCommitted: make(chan []byte),
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

// Propose implements replication.LogReplicator
// The following is true for kvLog.Propose but not necessarilty for other
// implementations of replication.LogReplicator: If Propose(x) returns, then
// after some amount of time without crashes, WaitCommitted returns x.
func (l *kvLog) Propose(ctx context.Context, data []byte) {
	select {
	case l.propose <- data:
	case <-l.stop:
	}
}

// WaitCommitted implements replication.LogReplicator
func (l *kvLog) WaitCommitted() <-chan []byte {
	return l.waitCommitted
}

// GetCommitted implements replication.LogReplicator
func (l *kvLog) GetCommitted(lo, hi, maxSize uint64) (ret [][]byte, err error) {
	size := uint64(0)
	for i := lo; i < hi; i++ {
		var v []byte
		v, err = l.get(i)
		if err != nil {
			if err == l.db.ErrNotFound() {
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
func (l *kvLog) get(i uint64) ([]byte, error) {
	dbkey := make([]byte, len(l.prefix)+8)
	copy(dbkey, l.prefix)
	binary.BigEndian.PutUint64(dbkey[len(l.prefix):], i)
	return l.db.Get(dbkey[:])
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
			l.db.Put(dbkey[:], prop)
			select {
			case <-l.stop:
				return
			case l.waitCommitted <- prop:
			}
		}
	}
}
