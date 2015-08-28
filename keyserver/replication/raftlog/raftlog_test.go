package raftlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"golang.org/x/net/context"

	"github.com/andres-erbsen/clock"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/keyserver/replication"
	"github.com/yahoo/coname/keyserver/replication/raftlog/proto"

	"github.com/yahoo/coname/keyserver/replication/raftlog/nettestutil"
)

const tick = time.Second

func chain(fs ...func()) func() {
	ret := func() {}
	for _, f := range fs {
		// the functions are copied to the heap, the closure refers to a unique copy of its own
		oldRet := ret
		thisF := f
		ret = func() { oldRet(); thisF() }
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

// raft replicas are numbered 1..n  and reside in array indices 0..n-1
// A copy of this function exists in server_test.go
func setupRaftLogCluster(t *testing.T, nReplicas, nStandbys int) (ret []replication.LogReplicator, clks []*clock.Mock, nw *nettestutil.Network, teardown func()) {
	m := nReplicas
	n := nReplicas + nStandbys
	replicaIDs := make([]uint64, 0, n)
	for i := uint64(0); i < uint64(n); i++ {
		replicaIDs = append(replicaIDs, 1+i)
	}

	addrs := make([]string, 0, n)
	nw = nettestutil.New(n)
	lookupDialerFrom := func(src int) func(uint64) proto.RaftClient {
		return func(dstPlus1 uint64) proto.RaftClient {
			cc, err := grpc.Dial(addrs[dstPlus1-1], grpc.WithInsecure(), grpc.WithDialer(
				func(addr string, timeout time.Duration) (net.Conn, error) {
					nc, err := net.DialTimeout("tcp", addr, timeout)
					return nw.Wrap(nc, src, int(dstPlus1-1)), err
				}))
			if err != nil {
				panic(err) // async dial should not err
			}
			return proto.NewRaftClient(cc)
		}
	}
	teardown = func() {}

	for i := 0; i < n; i++ {
		clk := clock.NewMock()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s := grpc.NewServer()
		db, dbDown := setupDB(t)
		l := New(
			uint64(i+1), replicaIDs[:m],
			db, nil,
			clk, tick,
			s, lookupDialerFrom(i),
		)
		go s.Serve(ln)

		ret = append(ret, l)
		clks = append(clks, clk)
		addrs = append(addrs, ln.Addr().String())
		teardown = chain(func() { s.Stop(); ln.Close(); l.Stop() }, dbDown, teardown)
	}

	for _, l := range ret {
		l.Start(0)
		go func(l replication.LogReplicator) {
			for _ = range l.LeaderHintSet() {
			}
		}(l)
	}
	return ret, clks, nw, teardown
}

func TestRaftLogStartStop1(t *testing.T) {
	_, _, _, teardown := setupRaftLogCluster(t, 1, 0)
	defer teardown()
}

func TestRaftLogStartStop1Standby1(t *testing.T) {
	_, _, _, teardown := setupRaftLogCluster(t, 1, 1)
	defer teardown()
}

func TestRaftLogStartStop3(t *testing.T) {
	_, _, _, teardown := setupRaftLogCluster(t, 3, 0)
	defer teardown()
}

func TestRaftLogStartStop5(t *testing.T) {
	_, _, _, teardown := setupRaftLogCluster(t, 5, 0)
	defer teardown()
}

type appendMachine struct {
	db  kv.DB
	log replication.LogReplicator

	state        []byte
	nextIndexLog uint64
	get          chan chan []byte

	stopOnce sync.Once
	stop     chan struct{}
	waitStop sync.WaitGroup
}

func openAppendMachine(db kv.DB, log replication.LogReplicator) *appendMachine {
	am := &appendMachine{db: db, log: log, stop: make(chan struct{}), get: make(chan chan []byte)}
	am.load()
	return am
}

func (am *appendMachine) Start() {
	am.waitStop.Add(1)
	go am.run()
}

func (am *appendMachine) Stop() {
	am.stopOnce.Do(func() {
		close(am.stop)
		am.waitStop.Wait()
	})
}

func (am *appendMachine) Get() []byte {
	ch := make(chan []byte)
	am.get <- ch
	return <-ch
}

func (am *appendMachine) run() {
	defer am.waitStop.Done()
	for {
		select {
		case ch := <-am.get:
			ch <- append([]byte{}, am.state...)
		case <-am.stop:
			return
		case stepLogEntry := <-am.log.WaitCommitted():
			switch {
			case stepLogEntry.Data != nil:
				am.state = append(am.state, stepLogEntry.Data...)
				am.nextIndexLog++
				am.persist()
			}
		}
	}
}

func (am *appendMachine) persist() {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], am.nextIndexLog)
	if err := am.db.Put([]byte{}, append(am.state, idx[:]...)); err != nil {
		panic(err)
	}
}

func (am *appendMachine) load() {
	var err error
	am.state, err = am.db.Get([]byte{})
	if err == am.db.ErrNotFound() {
		return
	}
	if err != nil {
		panic(err)
	}
	am.nextIndexLog = binary.BigEndian.Uint64(am.state[len(am.state)-8:])
	am.state = am.state[:len(am.state)-8]
}

func setupAppendMachineCluster(t *testing.T, nReplicas, nStandbys int) (ret []*appendMachine, clks []*clock.Mock, nw *nettestutil.Network, teardown func()) {
	rafts, clks, nw, teardown := setupRaftLogCluster(t, nReplicas, nStandbys)
	for _, r := range rafts {
		db, td := setupDB(t)
		am := openAppendMachine(db, r)
		am.Start()
		ret = append(ret, am)
		teardown = chain(am.Stop, td, teardown)
	}
	return ret, clks, nw, teardown
}

func TestAppendMachineStartStop1(t *testing.T) {
	_, _, _, teardown := setupAppendMachineCluster(t, 1, 0)
	defer teardown()
}

func TestAppendMachineStartStop3(t *testing.T) {
	_, _, _, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()
}

func TestAppendMachineStartStop5(t *testing.T) {
	_, _, _, teardown := setupAppendMachineCluster(t, 5, 0)
	defer teardown()
}

func TestAppendMachineEachProposeOneAndStop5(t *testing.T) {
	replicas, _, _, teardown := setupAppendMachineCluster(t, 5, 0)
	defer teardown()
	for i, am := range replicas {
		go am.log.Propose(context.Background(), replication.LogEntry{Data: []byte{byte(i)}})
	}
}

func isConsistentPrefix(a, b []byte) bool {
	l := len(a)
	if len(b) < l {
		l = len(b)
	}
	return bytes.Equal(a[:l], b[:l])
}

func checkReplicasConsistent(t *testing.T, states map[int][]byte) {
	for i, si := range states {
		for j, sj := range states {
			if !isConsistentPrefix(si, sj) {
				t.Errorf("logs of replicas %d and %d diverged: %s <> %s", 1+i, 1+j, si, sj)
			}
		}
	}
}

func checkMachinesConsistent(t *testing.T, ms []*appendMachine) {
	for i, mi := range ms {
		for j, mj := range ms {
			if a, b := mi.Get(), mj.Get(); !isConsistentPrefix(a, b) {
				t.Errorf("logs of replicas %d and %d diverged: %s <> %s", 1+i, 1+j, a, b)
			}
		}
	}
}

func syncTryPropose(am *appendMachine, clk *clock.Mock, prop []byte) {
	s := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { am.log.Propose(ctx, replication.LogEntry{Data: prop}); close(s) }()
	for i := 0; i < 30; i++ {
		select {
		case <-s:
			return
		default:
			clk.Add(tick)
		}
	}
	cancel()
}

func testAppendMachineEachProposeAndWait(t *testing.T, replicas []*appendMachine, clks []*clock.Mock, batchid, nProposeEach, laggards int) {
	remaining := make(map[int]map[string]struct{})
	for i := 0; i < len(replicas); i++ {
		remaining[i] = make(map[string]struct{})
	}

	const slen = 8
	for j := 0; j < nProposeEach; j++ {
		for i, am := range replicas {
			s := fmt.Sprintf("(%1d:%01d%03d)", i+1, batchid, j)
			if len(s) != slen {
				panic("slen mismatch")
			}
			remaining[i][s] = struct{}{}
			go am.log.Propose(context.Background(), replication.LogEntry{Data: []byte(s)})
		}
	}

	states := make(map[int][]byte)
	for len(remaining) > laggards {
		i := rand.Intn(len(replicas))
		clks[i].Add(tick)
		ss := replicas[i].Get()
		if prev, _ := states[i]; !bytes.Equal(ss[:len(prev)], prev) {
			t.Fatalf("replica %d changed its history", 1+i)
		}
		states[i] = ss
		checkReplicasConsistent(t, states)

		for si := 0; si < len(ss); si += slen {
			s := string(ss[si : si+slen])
			var j int
			_, err := fmt.Sscanf(s[:3], "(%1d:", &j)
			if err != nil {
				panic(err)
			}
			delete(remaining[j-1], s)
			if len(remaining[j-1]) == 0 {
				delete(remaining, j-1)
			}
		}

		// retry propose for everything that has not passed yet.
		// just one entry at a time, though -- this loop will run again.
		for s := range remaining[i] {
			syncTryPropose(replicas[i], clks[i], []byte(s))
			break
		}
	}
	if testing.Verbose() {
		for i := range replicas {
			if _, r := remaining[i]; !r {
				t.Log(string(replicas[i].Get()))
				break
			}
		}
	}
}

func majority(n int) int {
	return (n / 2) + 1
}

func partitionMajorityMinority(t *testing.T, nw *nettestutil.Network, n, offset int) {
	m := majority(n)
	main := make([]int, 0, m)
	encl := make([]int, 0, n-m)
	for i := 0; i < n; i++ {
		if (i+offset)%n < m {
			main = append(main, i)
		} else {
			encl = append(encl, i)
		}
	}
	nw.Partition(main, encl)
	if testing.Verbose() {
		for i := range main {
			main[i]++
		}
		for i := range encl {
			encl[i]++
		}
		t.Logf("partition! (%v, %v)", main, encl)
	}
}

func TestAppendMachineEachPropose1AndWait5(t *testing.T) {
	replicas, clks, _, teardown := setupAppendMachineCluster(t, 5, 0)
	defer teardown()
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 1, 0)
}

func TestAppendMachineEachPropose13AndWait3(t *testing.T) {
	replicas, clks, _, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 13, 0)
}

func TestAppendMachineEachPropose1WhilePartitioned3(t *testing.T) {
	replicas, clks, nw, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()
	partitionMajorityMinority(t, nw, 3, 0)
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 1, 1)
}

func TestAppendMachineEachPropose7Partitioned7AndWait3(t *testing.T) {
	replicas, clks, nw, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 7, 0)
	partitionMajorityMinority(t, nw, 3, 0)
	testAppendMachineEachProposeAndWait(t, replicas, clks, 1, 7, 1)
}

func TestAppendMachineEachPropose7Partitioned5Repartitioned13AndWait3(t *testing.T) {
	replicas, clks, nw, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 7, 0)
	partitionMajorityMinority(t, nw, 3, 0)
	testAppendMachineEachProposeAndWait(t, replicas, clks, 1, 5, 1)
	partitionMajorityMinority(t, nw, 3, 1)
	testAppendMachineEachProposeAndWait(t, replicas, clks, 2, 13, 1)
}

func TestRecoverFromDisconnect3(t *testing.T) {
	replicas, clks, nw, teardown := setupAppendMachineCluster(t, 3, 0)
	defer teardown()

	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 7, 0)
	t.Log("disconnected!")

	nw.Partition([]int{0}, []int{1}, []int{2})
	for j := 0; j < 100; j++ {
		i := rand.Intn(len(replicas))
		go replicas[i].log.Propose(context.Background(), replication.LogEntry{Data: []byte(fmt.Sprintf("(%1d:%01d%03d)", i+1, 1, j))})
		clks[i].Add(tick)
	}

	partitionMajorityMinority(t, nw, 3, 0)
	testAppendMachineEachProposeAndWait(t, replicas, clks, 2, 5, 1)
}

func partitionRandomly(t *testing.T, nw *nettestutil.Network, n int) {
	nparts := rand.Intn(n) + 1
	parts := make([][]int, nparts)
	for i := 0; i < n; i++ {
		p := rand.Intn(nparts)
		parts[p] = append(parts[p], i)
	}
	nw.Partition(parts...)
	if testing.Verbose() {
		for _, pp := range parts {
			for i := range pp {
				pp[i]++
			}
		}
		t.Logf("partition! %v", parts)
	}
}

func TestLots(t *testing.T) {
	replicas, clks, nw, teardown := setupAppendMachineCluster(t, 5, 0)
	defer teardown()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// log entries are proposed
	proposed := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(proposed)
		for j := 0; j < 1000; j++ {
			select {
			case <-stop:
				return
			case <-time.After(time.Microsecond * time.Duration(1*1000*rand.Float64())):
			}
			i := rand.Intn(len(replicas))
			go replicas[i].log.Propose(context.Background(), replication.LogEntry{Data: []byte(fmt.Sprintf("(%1d:%04d)", i+1, j))})
		}
	}()

	// time passes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Microsecond * time.Duration(5*1000*rand.Float64())):
			}
			i := rand.Intn(len(replicas))
			clks[i].Add(tick * time.Duration(rand.Intn(12)))
		}
	}()

	// network changes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Microsecond * time.Duration(50*1000*rand.Float64())):
			}
			if rand.Intn(3) == 1 {
				partitionMajorityMinority(t, nw, len(replicas), rand.Intn(len(replicas)))
			} else {
				partitionRandomly(t, nw, len(replicas))
			}
		}
	}()

	// evolution of states is tracked
	wantStates := make(chan chan map[int][]byte)
	go func() {
		states := make(map[int][]byte)
		for {
			select {
			case ch := <-wantStates:
				ch <- states
				return
			case <-time.After(time.Microsecond * time.Duration(10*1000*rand.Float64())):
			}
			i := rand.Intn(len(replicas))
			ss := replicas[i].Get()
			if prev, _ := states[i]; !bytes.Equal(ss[:len(prev)], prev) {
				t.Fatalf("replica %d changed its history", 1+i)
			}
		}
	}()

	// make everything okay again
	<-proposed
	close(stop)
	wg.Wait()
	nw.Partition()
	for j := 0; j < 30; j++ {
		for i := range replicas {
			clks[i].Add(tick)
		}
	}
	time.Sleep(10 * time.Millisecond)

	// check that there was no divergance
	ch := make(chan map[int][]byte)
	wantStates <- ch
	states := <-ch
	checkReplicasConsistent(t, states)

	testAppendMachineEachProposeAndWait(t, replicas, clks, 1, 7, 0)
}

func TestAppendMachineEachPropose1AndWait3Standby1(t *testing.T) {
	replicas, clks, _, teardown := setupAppendMachineCluster(t, 3, 1)
	defer teardown()
	testAppendMachineEachProposeAndWait(t, replicas, clks, 0, 1, 1)
}

func TestConfigurationChange3Add1Detailed(t *testing.T) {
	replicas, clks, _, teardown := setupAppendMachineCluster(t, 3, 1)
	defer teardown()

	go replicas[0].log.Propose(context.Background(), replication.LogEntry{Data: []byte("A")})
	go replicas[1].log.Propose(context.Background(), replication.LogEntry{Data: []byte("B")})
	go replicas[2].log.Propose(context.Background(), replication.LogEntry{Data: []byte("C")})

	for i := 0; i < 3; i++ {
		for len(replicas[i].Get()) < 3 {
			for j := 0; j < 3; j++ {
				clks[j].Add(tick)
			}
		}
	}

	for i := 0; i < 4; i++ {
		replicas[i].log.ApplyConfChange(&replication.ConfChange{NodeID: 4, Operation: replication.ConfChangeAddNode})
	}

	for len(replicas[3].Get()) < 3 {
		for j := 0; j < 4; j++ {
			clks[j].Add(tick)
		}
	}

	for i := 0; i < 4; i++ {
		for len(replicas[i].Get()) < 4 {
			replicas[3].log.Propose(context.Background(), replication.LogEntry{Data: []byte("D")})
			for j := 0; j < 4; j++ {
				clks[j].Add(tick)
			}
		}
	}

	states := make(map[int][]byte)
	for i := 0; i < 4; i++ {
		states[i] = replicas[i].Get()
	}
	checkReplicasConsistent(t, states)
}
