package raftlog

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/andres-erbsen/tlstestutil"
	"github.com/coreos/etcd/raft"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/kv/leveldbkv"
	"github.com/yahoo/coname/server/replication"
)

func chain(fs ...func()) func() {
	ret := func() {}
	for _, f := range fs {
		// the functions are copied to the heap, the closure refers to a unique copy of its own
		oldRet := ret
		ret = func() { oldRet(); f() }
	}
	return ret
}

func setupDB(t *testing.T) (db kv.DB, teardown func()) {
	dir, err := ioutil.TempDir("", "raftlog")
	if err != nil {
		t.Fatal(err)
	}
	teardown = func() { os.RemoveAll(dir) }
	ldb, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		teardown()
		t.Fatal(err)
	}
	teardown = chain(func() { ldb.Close() }, teardown)
	return leveldbkv.Wrap(ldb), teardown
}

func setupRaftLogCluster(t *testing.T, n int) (ret []replication.LogReplicator, teardown func()) {
	caCert, caPool, caKey := tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	tls := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert}

	peers := make([]raft.Peer, 0, n)
	for i := uint64(0); i < uint64(n); i++ {
		peers = append(peers, raft.Peer{ID: 1 + i})
	}

	addrs := make([]string, 0, n)
	lookupDialer := func(id uint64) (net.Conn, error) {
		return net.Dial("tcp", addrs[id-1])
	}

	for i := 0; i < n; i++ {
		c := &raft.Config{
			ID:              uint64(1 + i),
			ElectionTick:    10,
			HeartbeatTick:   1,
			MaxSizePerMsg:   4096,
			MaxInflightMsgs: 256,
		}
		db, dbDown := setupDB(t)
		teardown = chain(dbDown, teardown)
		l, err := Open(db, nil, c, peers, clock.New(), time.Millisecond, "localhost:0", tls, lookupDialer)
		if err != nil {
			teardown()
			t.Fatal(err)
		}
		ret = append(ret, l)
		teardown = chain(func() { l.Stop() }, teardown)
	}

	for _, l := range ret {
		addrs = append(addrs, l.(*raftLog).grpcListen.Addr().String())
	}

	for _, l := range ret {
		l.Start(0)
	}
	return ret, teardown
}

func TestRaftLogStartStop1(t *testing.T) {
	_, teardown := setupRaftLogCluster(t, 1)
	defer teardown()
}

func TestRaftLogStartStop3(t *testing.T) {
	_, teardown := setupRaftLogCluster(t, 3)
	defer teardown()
}

func TestRaftLogStartStop5(t *testing.T) {
	_, teardown := setupRaftLogCluster(t, 5)
	defer teardown()
}
