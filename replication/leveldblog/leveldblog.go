package leveldblog

import (
	"encoding/binary"
	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb/util"
	"github.com/yahoo/coname/internal/golang.org/x/net/context"
	"github.com/yahoo/coname/replication"
)

// LeveldbLog implements replication.ReplicatedLog using a NON-REPLICATED but
// persistent levelDB database.
type LeveldbLog struct {
	db         *leveldb.DB
	nextIndex  uint64
	skipBefore uint64

	propose       chan []byte
	waitCommitted chan []byte
	close         chan struct{}
	closed        chan struct{}
}

var _ replication.ReplicatedLog = (*LeveldbLog)(nil)

func NewLeveldbLog(db *leveldb.DB) *LeveldbLog {
	nextIndex := uint64(0)
	iter := db.NewIterator(util.BytesPrefix(nil), nil)
	if hasEntries := iter.Last(); hasEntries {
		nextIndex = binary.BigEndian.Uint64(iter.Key()) + 1
	}
	iter.Release()

	return &LeveldbLog{
		db:            db,
		nextIndex:     nextIndex,
		propose:       make(chan []byte, 100),
		waitCommitted: make(chan []byte),
		close:         make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (l *LeveldbLog) Start(lo uint64) error {
	l.skipBefore = lo
	go l.run()
	return nil
}

func (l *LeveldbLog) Close() error {
	close(l.close)
	<-l.closed
	return nil
}

func (l *LeveldbLog) Propose(ctx context.Context, data []byte) {
	l.propose <- data
}

func (l *LeveldbLog) WaitCommitted() <-chan []byte {
	return l.waitCommitted
}

func (l *LeveldbLog) GetCommitted(lo, hi, maxSize uint64) (ret [][]byte, err error) {
	size := uint64(0)
	for i := lo; i < hi; i++ {
		var v []byte
		v, err = l.get(i)
		if err != nil {
			return
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

func (l *LeveldbLog) get(i uint64) ([]byte, error) {
	var dbkey [8]byte
	binary.BigEndian.PutUint64(dbkey[:], i)
	return l.db.Get(dbkey[:], nil)
}

func (l *LeveldbLog) run() {
	defer close(l.closed)
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
