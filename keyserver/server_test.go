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

package keyserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/andres-erbsen/tlstestutil"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/keyserver/kv/tracekv"
	"github.com/yahoo/coname/keyserver/replication"
	"github.com/yahoo/coname/keyserver/replication/raftlog"
	"github.com/yahoo/coname/keyserver/replication/raftlog/nettestutil"
	raftproto "github.com/yahoo/coname/keyserver/replication/raftlog/proto"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/verifier"
	"github.com/yahoo/coname/vrf"
)

const (
	testingRealm = "testing"
	realmDomain  = "wonder.land"
	alice        = "alice@wonder.land"
	tick         = time.Second
	poll         = 100 * time.Microsecond
)

func dieOnCtrlC() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		panic("quit!")
	}()
}

func pprof() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

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
	dir, err := ioutil.TempDir("", "keyserver")
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
// A copy of this function exists in raftlog_test.go
func setupRaftLogCluster(t *testing.T, nReplicas, nStandbys int) (ret []replication.LogReplicator, dbs []kv.DB, clks []*clock.Mock, nw *nettestutil.Network, teardown func()) {
	m := nReplicas
	n := nReplicas + nStandbys
	replicaIDs := make([]uint64, 0, n)
	for i := uint64(0); i < uint64(n); i++ {
		replicaIDs = append(replicaIDs, 1+i)
	}

	addrs := make([]string, 0, n)
	nw = nettestutil.New(n)
	lookupDialerFrom := func(src int) func(uint64) raftproto.RaftClient {
		return func(dstPlus1 uint64) raftproto.RaftClient {
			cc, err := grpc.Dial(addrs[dstPlus1-1], grpc.WithInsecure(), grpc.WithDialer(
				func(addr string, timeout time.Duration) (net.Conn, error) {
					nc, err := net.DialTimeout("tcp", addr, timeout)
					return nw.Wrap(nc, src, int(dstPlus1-1)), err
				}))
			if err != nil {
				panic(err) // async dial should not err
			}
			return raftproto.NewRaftClient(cc)
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
		dbs = append(dbs, db)
		l := raftlog.New(
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
		go func(l replication.LogReplicator) {
			for _ = range l.LeaderHintSet() {
			}
		}(l)
	}
	return ret, dbs, clks, nw, teardown
}

func majorityQuorum(candidates []uint64) *proto.QuorumExpr {
	return &proto.QuorumExpr{Threshold: uint32(majority(len(candidates))), Candidates: candidates}
}

// setupKeyservers initializes everything needed to start a set of keyserver
// replicas, but does not actually start them yet
func setupKeyservers(t *testing.T, nReplicas int) (
	cfgs []*proto.ReplicaConfig, serverKeyGetters []func(string) (crypto.PrivateKey, error),
	clientKeyGetter func(string) (crypto.PrivateKey, error),
	clientConfig *proto.Config, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey, teardown func(),
) {
	caCert, caPool, caKey = tlstestutil.CA(t, nil)

	vrfPublic, vrfSecret, err := vrf.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	teardown = func() {}

	clientCert := tlstestutil.Cert(t, caCert, caKey, "client", nil)
	clientKeyGetter = func(id string) (crypto.PrivateKey, error) {
		switch id {
		case "client":
			return clientCert.PrivateKey, nil
		default:
			t.Fatalf("unknown key %s", id)
			return nil, nil
		}
	}

	pks := make(map[uint64]*proto.PublicKey)
	replicaIDs := []uint64{}
	pol := &proto.AuthorizationPolicy{}
	realmConfig := &proto.RealmConfig{
		RealmName:          testingRealm,
		Domains:            []string{realmDomain},
		VRFPublic:          vrfPublic,
		VerificationPolicy: pol,
		EpochTimeToLive:    proto.DurationStamp(time.Hour),
		ClientTLS: &proto.TLSConfig{
			RootCAs:      [][]byte{caCert.Raw},
			Certificates: []*proto.CertificateAndKeyID{{clientCert.Certificate, "client", nil}},
		},
	}
	clientConfig = &proto.Config{
		Realms: []*proto.RealmConfig{realmConfig},
	}
	for n := 0; n < nReplicas; n++ {
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			teardown()
			t.Fatal(err)
		}
		pked := &proto.PublicKey{PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pk[:]}}
		replicaID := proto.KeyID(pked)
		pks[replicaID] = pked
		replicaIDs = append(replicaIDs, replicaID)

		cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
		pcerts := []*proto.CertificateAndKeyID{{cert.Certificate, "tls", nil}}
		cfgs = append(cfgs, &proto.ReplicaConfig{
			KeyserverConfig: proto.KeyserverConfig{
				Realm:    testingRealm,
				ServerID: replicaID,
				VRFKeyID: "vrf",

				MinEpochInterval:      proto.DurationStamp(tick),
				MaxEpochInterval:      proto.DurationStamp(tick),
				ProposalRetryInterval: proto.DurationStamp(poll),
			},

			SigningKeyID:        "signing",
			ReplicaID:           replicaID,
			PublicAddr:          "localhost:0",
			VerifierAddr:        "localhost:0",
			HKPAddr:             "localhost:0",
			PublicTLS:           proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			VerifierTLS:         proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			HKPTLS:              proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			ClientTimeout:       proto.DurationStamp(time.Hour),
			LaggingVerifierScan: 1000 * 1000 * 1000,
		})
		serverKeyGetters = append(serverKeyGetters, func(keyid string) (crypto.PrivateKey, error) {
			switch keyid {
			case "vrf":
				return vrfSecret, nil
			case "signing":
				return sk, nil
			case "tls":
				return cert.PrivateKey, nil
			default:
				panic("unknown key requested in test")
			}
		})
	}
	pol.PublicKeys = pks
	pol.PolicyType = &proto.AuthorizationPolicy_Quorum{Quorum: majorityQuorum(replicaIDs)}
	return
}

func TestOneKeyserverStartStop(t *testing.T) {
	testKeyserverStartStop(t, 1)
}

func TestThreeKeyserversStartStop(t *testing.T) {
	testKeyserverStartStop(t, 3)
}

func testKeyserverStartStop(t *testing.T, nReplicas int) {
	cfgs, gks, _, ccfg, _, _, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()
	kss := []*Keyserver{}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], ccfg.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		kss = append(kss, ks)
	}
	for _, ks := range kss {
		ks.Stop()
	}
}

func TestKeyserverStartProgressStop(t *testing.T) {
	pprof()
	nReplicas := 3
	cfgs, gks, _, ccfg, _, _, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()

	// the db writes are test output. We are waiting for epoch 3 to be ratified
	// by all replicas as a primitive progress check.
	kss := []*Keyserver{}
	var done sync.WaitGroup
	done.Add(nReplicas)
	for i := 0; i < nReplicas; i++ {
		var closeOnce sync.Once
		dbs[i] = tracekv.WithSimpleTracing(dbs[i], func(update tracekv.Update) {
			if update.IsDeletion || len(update.Key) < 1 || update.Key[0] != tableRatificationsPrefix {
				return
			}
			epoch := binary.BigEndian.Uint64(update.Key[1 : 1+8])
			if epoch == 3 {
				closeOnce.Do(func() { done.Done() })
			}
		})

		ks, err := Open(cfgs[i], dbs[i], logs[i], ccfg.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		kss = append(kss, ks)
	}

	progressCh := make(chan struct{})
	go func() {
		done.Wait()
		close(progressCh)
	}()

loop:
	for {
		select {
		case <-progressCh:
			break loop
		default:
			i := mathrand.Intn(len(kss))
			clks[i].Add(tick)
		}
	}

	for _, ks := range kss {
		ks.Stop()
	}
	teardown2()
	teardown()

	if testing.Verbose() {
		time.Sleep(time.Millisecond)
		n := runtime.NumGoroutine()
		stackBuf := make([]byte, 1014)
		var l int
		for l = runtime.Stack(stackBuf, true); l == len(stackBuf) && l < 128*1024; {
			stackBuf = append(stackBuf, stackBuf...)
		}
		t.Logf("%d goroutines in existence after Stop:\n%s", n, stackBuf[:l])
	}
}

func doUpdate(
	t *testing.T, ks *Keyserver, clientConfig *proto.Config, clientTLS *tls.Config, caPool *x509.CertPool, now time.Time,
	name string, version uint64, profileContents proto.Profile,
) *proto.EncodedProfile {
	conn, err := grpc.Dial(ks.publicListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	publicC := proto.NewE2EKSPublicClient(conn)

	// First, do a lookup to retrieve the index
	lookup, err := publicC.Lookup(context.Background(), &proto.LookupRequest{
		UserId: name,
		// We don't care about any signatures here; the server just needs to tell us the index.
		QuorumRequirement: &proto.QuorumExpr{
			Threshold:      0,
			Candidates:     []uint64{},
			Subexpressions: []*proto.QuorumExpr{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := lookup.Index

	// Do the update
	profile := proto.EncodedProfile{
		Profile: profileContents,
	}
	profile.UpdateEncoding()
	var commitment [64]byte
	sha3.ShakeSum256(commitment[:], profile.Encoding)
	entry := proto.EncodedEntry{
		Entry: proto.Entry{
			Index:   index,
			Version: version,
			UpdatePolicy: &proto.AuthorizationPolicy{
				PublicKeys: make(map[uint64]*proto.PublicKey),
				PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
					Threshold:      0,
					Candidates:     []uint64{},
					Subexpressions: []*proto.QuorumExpr{},
				},
				}},
			ProfileCommitment: commitment[:],
		},
	}
	entry.UpdateEncoding()
	proof, err := publicC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            name,
			QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proof.Profile.Encoding, profile.Encoding; !bytes.Equal(got, want) {
		t.Errorf("updated profile didn't roundtrip: %x != %x", got, want)
	}
	_, err = coname.VerifyLookup(clientConfig, name, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	return &profile
}

func waitForFirstEpoch(ks *Keyserver, quorum *proto.QuorumExpr) {
	ks.blockingLookup(context.Background(), &proto.LookupRequest{
		UserId:            alice,
		QuorumRequirement: quorum,
	}, 1)
}

func stoppableSyncedClocks(clks []*clock.Mock) chan<- struct{} {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				for _, clk := range clks {
					clk.Add(tick)
				}
			}
		}
	}()
	return done
}

func TestKeyserverAbsentLookup(t *testing.T) {
	dieOnCtrlC()
	pprof()
	nReplicas := 3
	cfgs, gks, ck, clientConfig, _, _, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()

	kss := []*Keyserver{}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], clientConfig.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.Start()
		defer ks.Stop()
		kss = append(kss, ks)
	}

	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.Dial(kss[0].publicListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSPublicClient(conn)

	proof, err := c.Lookup(context.Background(), &proto.LookupRequest{
		UserId:            alice,
		QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := coname.VerifyLookup(clientConfig, alice, proof, clks[0].Now())
	if err != nil {
		t.Fatal(err)
	}
	if keys != nil {
		t.Fatalf("Got back keys for a nonexistent profile")
	}
}

func TestKeyserverRoundtrip(t *testing.T) {
	nReplicas := 3
	cfgs, gks, ck, clientConfig, _, caPool, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()

	kss := []*Keyserver{}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], clientConfig.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		defer ks.Stop()
		kss = append(kss, ks)
	}

	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	profile := doUpdate(t, kss[0], clientConfig, clientTLS, caPool, clks[0].Now(), alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(kss[0].publicListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSPublicClient(conn)

	proof, err := c.Lookup(context.Background(), &proto.LookupRequest{
		UserId:            alice,
		QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proof.Profile.Encoding, profile.Encoding; !bytes.Equal(got, want) {
		t.Errorf("profile didn't roundtrip: %x != %x", got, want)
	}
	_, err = coname.VerifyLookup(clientConfig, alice, proof, clks[0].Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyserverUpdateFailsWithoutVersionIncrease(t *testing.T) {
	nReplicas := 3
	cfgs, gks, ck, clientConfig, _, caPool, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()

	kss := []*Keyserver{}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], clientConfig.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		defer ks.Stop()
		kss = append(kss, ks)
	}

	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	doUpdate(t, kss[0], clientConfig, clientTLS, caPool, clks[0].Now(), alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(kss[1].publicListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	profile := proto.EncodedProfile{
		Profile: proto.Profile{
			Nonce: []byte("NONCE"),
			Keys:  map[string][]byte{"abc": []byte{3, 2, 3}, "xyz": []byte("TEST 456")},
		},
	}
	profile.UpdateEncoding()
	var commitment [64]byte
	sha3.ShakeSum256(commitment[:], profile.Encoding)
	entry := proto.EncodedEntry{
		Entry: proto.Entry{
			Version: 0,
			UpdatePolicy: &proto.AuthorizationPolicy{
				PublicKeys: make(map[uint64]*proto.PublicKey),
				PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
					Threshold:      0,
					Candidates:     []uint64{},
					Subexpressions: []*proto.QuorumExpr{},
				}},
			},
			ProfileCommitment: commitment[:],
		},
	}
	entry.UpdateEncoding()
	updateC := proto.NewE2EKSPublicClient(conn)
	_, err = updateC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            alice,
			QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
		},
	})
	if err == nil {
		t.Fatalf("update went through despite failure to increment version")
	}
}

func TestKeyserverUpdate(t *testing.T) {
	nReplicas := 3
	cfgs, gks, ck, clientConfig, _, caPool, _, teardown := setupKeyservers(t, nReplicas)
	defer teardown()
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	defer teardown2()

	kss := []*Keyserver{}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], clientConfig.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		defer ks.Stop()
		kss = append(kss, ks)
	}

	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	doUpdate(t, kss[0], clientConfig, clientTLS, caPool, clks[0].Now(), alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	doUpdate(t, kss[2], clientConfig, clientTLS, caPool, clks[0].Now(), alice, 1, proto.Profile{
		Nonce: []byte("XYZNONCE"),
		Keys:  map[string][]byte{"abc": []byte{4, 5, 6}, "qwop": []byte("TEST MOOOO")},
	})
}

// setupVerifier initializes a verifier, but does not start it and does not
// wait for it to sign anything.
func setupVerifier(t *testing.T, keyserverVerif *proto.AuthorizationPolicy, keyserverAddr string, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey) (cfg *proto.VerifierConfig, getKey func(string) (crypto.PrivateKey, error), db kv.DB, sv *proto.PublicKey, teardown func()) {
	dir, err := ioutil.TempDir("", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	teardown = chain(func() { os.RemoveAll(dir) })
	ldb, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		teardown()
		t.Fatal(err)
	}
	teardown = chain(func() { ldb.Close() }, teardown)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		teardown()
		t.Fatal(err)
	}
	sv = &proto.PublicKey{PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pk[:]}}

	cert := tlstestutil.Cert(t, caCert, caKey, fmt.Sprintf("verifier %x", proto.KeyID(sv)), nil)
	getKey = func(keyid string) (crypto.PrivateKey, error) {
		switch keyid {
		case "signing":
			return sk, nil
		case "tls":
			return cert.PrivateKey, nil
		default:
			panic("unknown key requested in tests [" + keyid + "]")
		}
	}
	cfg = &proto.VerifierConfig{
		Realm:                testingRealm,
		KeyserverAddr:        keyserverAddr,
		InitialKeyserverAuth: *keyserverVerif,
		SigningKeyID:         "signing",

		ID:  proto.KeyID(sv),
		TLS: &proto.TLSConfig{RootCAs: [][]byte{caCert.Raw}, Certificates: []*proto.CertificateAndKeyID{{cert.Certificate, "tls", nil}}},
	}
	db = leveldbkv.Wrap(ldb)
	return
}

// setupRealm initializes nReplicas keyserver replicas and nVerifiers
// verifiers, and then waits until each one of them has signed an epoch.
func setupRealm(t *testing.T, nReplicas, nVerifiers int) (
	kss []*Keyserver, caPool *x509.CertPool, clks []*clock.Mock, verifiers []uint64,
	clientKeyGetter func(string) (crypto.PrivateKey, error), clientConfig *proto.Config, teardown func(),
) {
	cfgs, gks, ck, clientConfig, caCert, caPool, caKey, teardown := setupKeyservers(t, nReplicas)
	logs, dbs, clks, _, teardown2 := setupRaftLogCluster(t, nReplicas, 0)
	teardown = chain(teardown2, teardown)

	var ksDone sync.WaitGroup
	ksDone.Add(nReplicas)
	for i := range dbs {
		var ksDoneOnce sync.Once
		dbs[i] = tracekv.WithSimpleTracing(dbs[i], func(update tracekv.Update) {
			// We are waiting for an epoch to be ratified (in case there are no
			// verifiers, blocking on them does not help).
			if update.IsDeletion || len(update.Key) < 1 || update.Key[0] != tableVerifierLogPrefix {
				return
			}
			ksDoneOnce.Do(func() { ksDone.Done() })
		})
	}

	type doneVerifier struct {
		teardown func()
		id       uint64
	}
	ksBarrier := make(chan struct{})
	doneVerifiers := make(chan doneVerifier, nVerifiers)
	vpks := make([]*proto.PublicKey, nVerifiers)
	for i := 0; i < nVerifiers; i++ {
		vrBarrier := make(chan struct{})
		var verifierTeardown func()
		var vcfg *proto.VerifierConfig
		var doneOnce sync.Once
		dbs[0] = tracekv.WithSimpleTracing(dbs[0], func(update tracekv.Update) {
			// We are waiting for epoch 1 to be ratified by the verifier and
			// reach the client because before that lookups requiring this
			// verifier will immediately fail.
			if len(update.Key) < 1 || update.Key[0] != tableRatificationsPrefix {
				return
			}
			<-vrBarrier
			epoch := binary.BigEndian.Uint64(update.Key[1 : 1+8])
			id := binary.BigEndian.Uint64(update.Key[1+8 : 1+8+8])
			if id == vcfg.ID && epoch == 1 {
				doneOnce.Do(func() { doneVerifiers <- doneVerifier{verifierTeardown, vcfg.ID} })
			}
		})
		go func(i int) {
			var vdb kv.DB
			<-ksBarrier
			var getKey func(string) (crypto.PrivateKey, error)
			vcfg, getKey, vdb, vpks[i], verifierTeardown = setupVerifier(t, clientConfig.Realms[0].VerificationPolicy,
				kss[i%nReplicas].verifierListen.Addr().String(), caCert, caPool, caKey)

			vr, err := verifier.Start(vcfg, vdb, getKey)
			if err != nil {
				t.Fatal(err)
			}
			verifierTeardown = chain(vr.Stop, verifierTeardown)
			close(vrBarrier)
		}(i)
	}
	for i := range cfgs {
		ks, err := Open(cfgs[i], dbs[i], logs[i], clientConfig.Realms[0].VerificationPolicy, clks[i], gks[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		ks.insecureSkipEmailProof = true
		ks.Start()
		teardown = chain(ks.Stop, teardown)
		kss = append(kss, ks)
	}
	close(ksBarrier)

	ksDoneCh := make(chan struct{})
	go func() {
		ksDone.Wait()
		close(ksDoneCh)
	}()

loop:
	for {
		select {
		case <-time.After(poll):
			for _, clk := range clks {
				clk.Add(tick)
			}
		case <-ksDoneCh:
			break loop
		}
	}
	for i := 0; i < nVerifiers; i++ {
		v := <-doneVerifiers
		verifiers = append(verifiers, v.id)
		teardown = chain(v.teardown, teardown)
	}
	pol := copyAuthorizationPolicy(clientConfig.Realms[0].VerificationPolicy)
	pol.PolicyType = &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
		Subexpressions: []*proto.QuorumExpr{pol.GetQuorum()},
		Threshold:      uint32(1 + nVerifiers),
		Candidates:     verifiers,
	}}
	for i := 0; i < nVerifiers; i++ {
		pol.PublicKeys[proto.KeyID(vpks[i])] = vpks[i]
	}
	clientConfig.Realms[0].VerificationPolicy = pol
	return kss, caPool, clks, verifiers, ck, clientConfig, teardown
}

func copyAuthorizationPolicy(pol *proto.AuthorizationPolicy) *proto.AuthorizationPolicy {
	pks := make(map[uint64]*proto.PublicKey)
	for id, pk := range pol.PublicKeys {
		pks[id] = pk
	}
	return &proto.AuthorizationPolicy{
		PublicKeys: pks,
		PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
			Candidates: append([]uint64{}, pol.GetQuorum().Candidates...),
			Threshold:  pol.GetQuorum().Threshold,
		}},
	}
}

func TestKeyserverLookupRequireThreeVerifiers(t *testing.T) {
	dieOnCtrlC()
	kss, caPool, clks, verifiers, ck, clientConfig, teardown := setupRealm(t, 3, 3)
	defer teardown()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	profile := doUpdate(t, kss[0], clientConfig, clientTLS, caPool, clks[0].Now(), alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(kss[0].publicListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSPublicClient(conn)
	proof, err := c.Lookup(context.Background(), &proto.LookupRequest{
		UserId:            alice,
		QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proof.Profile.Encoding, profile.Encoding; !bytes.Equal(got, want) {
		t.Errorf("profile didn't roundtrip: %x != %x", got, want)
	}
	if got, want := len(proof.Ratifications), majority(len(kss))+len(verifiers); got < want {
		t.Errorf("expected at least %d sehs, got %d", got, want)
	}
	_, err = coname.VerifyLookup(clientConfig, alice, proof, clks[0].Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyserverHKP(t *testing.T) {
	kss, caPool, clks, _, ck, clientConfig, teardown := setupRealm(t, 1, 0)
	ks := kss[0]
	defer teardown()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)
	waitForFirstEpoch(kss[0], clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}

	pgpKeyRef := []byte("this-is-alices-pgp-key")
	doUpdate(t, ks, clientConfig, clientTLS, caPool, clks[0].Now(), alice, 0, proto.Profile{
		Nonce: []byte("definitely used only once"),
		Keys:  map[string][]byte{"pgp": pgpKeyRef},
	})

	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: clientTLS,
	}}
	url := "https://" + ks.hkpListen.Addr().String() + "/pks/lookup?op=get&search=" + alice
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Status != "200 OK" {
		b, e := ioutil.ReadAll(resp.Body)
		t.Fatalf("%s (%s)", b, e)
	}

	pgpBlock, err := armor.Decode(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := pgpBlock.Type, "PGP PUBLIC KEY BLOCK"; got != want {
		t.Error("pgpBlock.Type: got %v but wanted %v", got, want)
	}
	if got, want := len(pgpBlock.Header), 0; got != want {
		t.Error("len(pgpBlock.Header): got %v but wanted %v", got, want)
	}
	pgpKey, err := ioutil.ReadAll(pgpBlock.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pgpKey, pgpKeyRef; !bytes.Equal(got, want) {
		t.Error("pgpKey: got %q but wanted %q", got, want)
	}
}
