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
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
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
	"github.com/yahoo/coname/keyserver/replication/raftlog/nettestutil"
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

func tlsConfigFromCertKeyIDClientCA(cert tls.Certificate, keyid string, clientCA *x509.Certificate) proto.TLSConfig {
	return proto.TLSConfig{
		Certificates: []*proto.CertificateAndKeyID{{cert.Certificate, keyid, nil}},
		RootCAs:      [][]byte{clientCA.Raw},
		ClientCAs:    [][]byte{clientCA.Raw},
		ClientAuth:   proto.REQUIRE_AND_VERIFY_CLIENT_CERT,
	}
}

type replicaTestingHooks struct {
	dbDir   string
	leveldb *leveldb.DB
	db      kv.DB

	pcfg          *proto.ReplicaConfig
	signingPublic *proto.PublicKey
	keyGetters    func(string) (crypto.PrivateKey, error)
	id            uint64

	serverClock, replicationClock *clock.Mock

	server *Keyserver // not initialized in setupReplica
}

func (r *replicaTestingHooks) teardown() {
	if r.server != nil {
		r.server.Stop()
	}
	if r.leveldb != nil {
		r.leveldb.Close()
	}
	if r.dbDir != "" {
		os.RemoveAll(r.dbDir)
	}
}

func setupReplica(t *testing.T,
	replicaCA *x509.Certificate, replicaCAKey *ecdsa.PrivateKey,
	verifierCA *x509.Certificate,
	clientCA *x509.Certificate,
	vrfSecret *[64]byte,
) (ret *replicaTestingHooks) {
	ret = new(replicaTestingHooks)
	pkRaw, signingSecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ret.signingPublic = &proto.PublicKey{PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pkRaw[:]}}
	ret.id = proto.KeyID(ret.signingPublic)

	tlsCert := tlstestutil.Cert(t, replicaCA, replicaCAKey, "127.0.0.1", nil)
	tlsSecret := tlsCert.PrivateKey

	ret.dbDir, err = ioutil.TempDir("", "keyserver")
	if err != nil {
		t.Fatal(err)
	}
	ret.leveldb, err = leveldb.OpenFile(ret.dbDir, nil)
	if err != nil {
		ret.teardown()
		t.Fatal(err)
	}
	ret.db = leveldbkv.Wrap(ret.leveldb)

	ret.pcfg = &proto.ReplicaConfig{
		SigningKeyID: "signing",
		ReplicaID:    ret.id,

		RaftAddr:      nettestutil.MustReserveListener(t, "tcp", "localhost:0"),
		RaftTLS:       tlsConfigFromCertKeyIDClientCA(tlsCert, "tls", replicaCA),
		RaftHeartbeat: proto.DurationStamp(tick),

		VerifierAddr:        nettestutil.MustReserveListener(t, "tcp", "localhost:0"),
		VerifierTLS:         tlsConfigFromCertKeyIDClientCA(tlsCert, "tls", verifierCA),
		LaggingVerifierScan: 1000 * 1000 * 1000,

		PublicAddr:    nettestutil.MustReserveListener(t, "tcp", "localhost:0"),
		PublicTLS:     tlsConfigFromCertKeyIDClientCA(tlsCert, "tls", clientCA),
		HKPAddr:       nettestutil.MustReserveListener(t, "tcp", "localhost:0"),
		HKPTLS:        tlsConfigFromCertKeyIDClientCA(tlsCert, "tls", clientCA),
		ClientTimeout: proto.DurationStamp(time.Hour),
	}

	ret.keyGetters = func(keyid string) (crypto.PrivateKey, error) {
		switch keyid {
		case "vrf":
			return vrfSecret, nil
		case "signing":
			return signingSecret, nil
		case "tls":
			return tlsSecret, nil
		default:
			panic("unknown key requested in test")
		}

	}
	ret.replicationClock = clock.NewMock()
	ret.serverClock = clock.NewMock()
	return
}

type keyserverTestingHooks struct {
	cfg      *proto.KeyserverConfig
	replicas []*replicaTestingHooks

	vrfPublic []byte
	vrfSecret *[64]byte

	clientCA, verifierCA, replicaCA          *x509.Certificate
	clientCAKey, verifierCAKey, replicaCAKey *ecdsa.PrivateKey

	t *testing.T
}

func (k *keyserverTestingHooks) teardown() {
	for _, r := range k.replicas {
		if r.server != nil {
			r.server.Stop()
		}
		r.teardown()
	}
}

func setupReplicatedKeyserver(t *testing.T, nReplicas int) (ret *keyserverTestingHooks) {
	ret = new(keyserverTestingHooks)
	ret.t = t
	ret.clientCA, _, ret.clientCAKey = tlstestutil.CA(t, nil)
	ret.verifierCA, _, ret.verifierCAKey = tlstestutil.CA(t, nil)
	ret.replicaCA, _, ret.replicaCAKey = tlstestutil.CA(t, nil)

	var err error
	ret.vrfPublic, ret.vrfSecret, err = vrf.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < nReplicas; i++ {
		ret.replicas = append(ret.replicas, setupReplica(t, ret.replicaCA, ret.replicaCAKey, ret.verifierCA, ret.clientCA, ret.vrfSecret))
	}

	ret.cfg = &proto.KeyserverConfig{
		Realm:    testingRealm,
		ServerID: 0, // TODO: remove this field (superseded by "Realm")
		VRFKeyID: "vrf",

		MinEpochInterval:      proto.DurationStamp(tick),
		MaxEpochInterval:      proto.DurationStamp(tick),
		ProposalRetryInterval: proto.DurationStamp(poll),

		InsecureSkipEmailProof: true,
	}
	for i := 0; i < nReplicas; i++ {
		ret.cfg.InitialReplicas = append(ret.cfg.InitialReplicas, &proto.Replica{
			PublicKeys: []*proto.PublicKey{ret.replicas[i].signingPublic},
			ID:         ret.replicas[i].id,
			RaftAddr:   ret.replicas[i].pcfg.RaftAddr,
		})
	}

	for i := 0; i < nReplicas; i++ {
		r := ret.replicas[i] // explicit reference, not copy
		r.pcfg.KeyserverConfig = *ret.cfg

		// NOTE: one could mock the log here to emulate log entry loss/duplication/reordering (to test keyserver-replication interface)
		// NOTE: one could use a mock connection in mkLog implementation of dialPeer to emulate network failures (to test replication-network interface)
		r.server, err = Open(r.pcfg, r.db, nettestutil.Listen, mkRaftLog, r.serverClock, r.keyGetters, nil)
		if err != nil {
			ret.teardown()
			t.Fatal(err)
		}
		r.server.Start()
	}
	return
}

func (k *keyserverTestingHooks) clocks() (ret []*clock.Mock) {
	for _, r := range k.replicas {
		ret = append(ret, r.serverClock, r.replicationClock)
	}
	return ret
}

func majorityQuorum(candidates []uint64) *proto.QuorumExpr {
	return &proto.QuorumExpr{Threshold: uint32(majority(len(candidates))), Candidates: candidates}
}

func (k *keyserverTestingHooks) realmConfig() *proto.RealmConfig {
	ret := &proto.RealmConfig{
		RealmName:          testingRealm,
		Domains:            []string{realmDomain},
		VRFPublic:          k.vrfPublic,
		VerificationPolicy: &proto.AuthorizationPolicy{PublicKeys: make(map[uint64]*proto.PublicKey)},
		EpochTimeToLive:    proto.DurationStamp(time.Hour),
		Addr:               k.replicas[0].pcfg.PublicAddr,
	}
	replicaIDs := []uint64{}
	for _, r := range k.replicas {
		ret.VerificationPolicy.PublicKeys[r.id] = r.signingPublic
		replicaIDs = append(replicaIDs, r.id)
	}
	ret.VerificationPolicy.PolicyType = &proto.AuthorizationPolicy_Quorum{Quorum: majorityQuorum(replicaIDs)}
	return ret
}

func (k *keyserverTestingHooks) setupClient() (*proto.Config, func(id string) (crypto.PrivateKey, error)) {
	clientCert := tlstestutil.Cert(k.t, k.clientCA, k.clientCAKey, "client", nil)
	clientKeyGetter := func(id string) (crypto.PrivateKey, error) {
		switch id {
		case "client":
			return clientCert.PrivateKey, nil
		default:
			k.t.Fatalf("unknown key requested: %q", id)
			return nil, nil
		}
	}
	realm := k.realmConfig()
	realm.ClientTLS = &proto.TLSConfig{
		RootCAs:      [][]byte{k.replicaCA.Raw},
		Certificates: []*proto.CertificateAndKeyID{{clientCert.Certificate, "client", nil}},
	}
	return &proto.Config{Realms: []*proto.RealmConfig{realm}}, clientKeyGetter
}

func TestOneKeyserverStartStop(t *testing.T) {
	testKeyserverStartStop(t, 1)
}

func TestThreeKeyserversStartStop(t *testing.T) {
	testKeyserverStartStop(t, 3)
}

func testKeyserverStartStop(t *testing.T, nReplicas int) {
	k := setupReplicatedKeyserver(t, nReplicas)
	k.teardown()
}

/*
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
*/

func doUpdate(k *keyserverTestingHooks,
	name string, sk *[ed25519.PrivateKeySize]byte, pk *proto.PublicKey, version uint64, profileContents proto.Profile,
) (*proto.EncodedEntry, *proto.EncodedProfile) {

	clientConfig, ck := k.setupClient()
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}
	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		k.t.Fatal(err)
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
		k.t.Fatal(err)
	}
	index := lookup.Index

	// Do the update
	var keyidBytes [8]byte
	sha3.ShakeSum256(keyidBytes[:], proto.MustMarshal(pk))
	keyid := binary.BigEndian.Uint64(keyidBytes[:8])

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
				PublicKeys: map[uint64]*proto.PublicKey{keyid: pk},
				PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
					Threshold:      1,
					Candidates:     []uint64{keyid},
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
			Signatures: map[uint64][]byte{keyid: ed25519.Sign(sk, entry.Encoding)[:]},
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            name,
			QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
		},
	})
	if err != nil {
		k.t.Fatal(err)
	}
	if got, want := proof.Profile.Encoding, profile.Encoding; !bytes.Equal(got, want) {
		k.t.Errorf("updated profile didn't roundtrip: %x != %x", got, want)
	}
	_, err = coname.VerifyLookup(clientConfig, name, proof, k.clocks()[0].Now())
	if err != nil {
		k.t.Fatal(err)
	}
	return &entry, &profile
}

func doRegister(
	k *keyserverTestingHooks,
	name string, version uint64, profileContents proto.Profile,
) (*[ed25519.PrivateKeySize]byte, *proto.PublicKey, *proto.EncodedEntry, *proto.EncodedProfile) {
	// Generate keys
	edpk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		k.t.Fatal(err)
	}
	pk := &proto.PublicKey{&proto.PublicKey_Ed25519{Ed25519: edpk[:]}}
	e, p := doUpdate(k, name, sk, pk, version, profileContents)
	return sk, pk, e, p
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
	k := setupReplicatedKeyserver(t, nReplicas)
	defer k.teardown()
	clks := k.clocks()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	clientConfig, ck := k.setupClient()

	waitForFirstEpoch(k.replicas[0].server, clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
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
	k := setupReplicatedKeyserver(t, nReplicas)
	defer k.teardown()
	clks := k.clocks()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}

	waitForFirstEpoch(k.replicas[0].server, clientConfig.Realms[0].VerificationPolicy.GetQuorum())
	_, _, _, profile := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
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
	k := setupReplicatedKeyserver(t, nReplicas)
	defer k.teardown()
	clks := k.clocks()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}

	waitForFirstEpoch(k.replicas[0].server, clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	_, _, aliceEntry, aliceProfile := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	updateC := proto.NewE2EKSPublicClient(conn)
	_, err = updateC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   *aliceEntry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: *aliceProfile,
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
	k := setupReplicatedKeyserver(t, nReplicas)
	defer k.teardown()
	clks := k.clocks()
	stop := stoppableSyncedClocks(clks)
	defer close(stop)

	clientConfig, _ := k.setupClient()
	waitForFirstEpoch(k.replicas[0].server, clientConfig.Realms[0].VerificationPolicy.GetQuorum())

	sk, pk, _, _ := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	doUpdate(k, alice, sk, pk, 1, proto.Profile{
		Nonce: []byte("XYZNONCE"),
		Keys:  map[string][]byte{"abc": []byte{4, 5, 6}, "qwop": []byte("TEST MOOOO")},
	})
}

// setupVerifier initializes a verifier, but does not start it and does not
// wait for it to sign anything.
func setupVerifier(t *testing.T, keyserverVerif *proto.AuthorizationPolicy, keyserverAddr string, replicaCACert, verifierCACert *x509.Certificate, verifierCAKey *ecdsa.PrivateKey) (cfg *proto.VerifierConfig, getKey func(string) (crypto.PrivateKey, error), db kv.DB, sv *proto.PublicKey, teardown func()) {
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

	cert := tlstestutil.Cert(t, verifierCACert, verifierCAKey, fmt.Sprintf("verifier %x", proto.KeyID(sv)), nil)
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
		TLS: &proto.TLSConfig{RootCAs: [][]byte{replicaCACert.Raw}, Certificates: []*proto.CertificateAndKeyID{{cert.Certificate, "tls", nil}}},
	}
	db = leveldbkv.Wrap(ldb)
	return
}

// setupRealm initializes nReplicas keyserver replicas and nVerifiers
// verifiers, and then waits until each one of them has signed an epoch.
func setupRealm(t *testing.T, nReplicas, nVerifiers int) (
	k *keyserverTestingHooks, authPol *proto.AuthorizationPolicy, teardown func(),
) {
	k = setupReplicatedKeyserver(t, nReplicas)
	teardown = k.teardown
	stopClocks := stoppableSyncedClocks(k.clocks())
	defer close(stopClocks)
	waitForFirstEpoch(k.replicas[0].server, k.realmConfig().VerificationPolicy.GetQuorum())

	var verifiers []uint64
	var vpks []*proto.PublicKey
	for i := 0; i < nVerifiers; i++ {
		vcfg, gk, db, pk, vteardown := setupVerifier(t, k.realmConfig().VerificationPolicy, k.replicas[0].pcfg.VerifierAddr, k.replicaCA, k.verifierCA, k.verifierCAKey)
		verifier, err := verifier.Start(vcfg, db, gk)
		if err != nil {
			t.Fatal(err)
		}
		verifiers = append(verifiers, proto.KeyID(pk))
		vpks = append(vpks, pk)
		teardown = chain(verifier.Stop, vteardown, teardown)
	}
	authPol = copyAuthorizationPolicy(k.realmConfig().VerificationPolicy)
	authPol.PolicyType = &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
		Threshold:      uint32(1 + nVerifiers),
		Subexpressions: []*proto.QuorumExpr{authPol.GetQuorum()},
		Candidates:     verifiers,
	}}
	for i := 0; i < nVerifiers; i++ {
		authPol.PublicKeys[proto.KeyID(vpks[i])] = vpks[i]
	}
	waitForFirstEpoch(k.replicas[0].server, authPol.GetQuorum())
	return k, authPol, teardown
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
	k, policyWithVerifiers, teardown := setupRealm(t, 3, 3)
	defer teardown()
	stop := stoppableSyncedClocks(k.clocks())
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientConfig.Realms[0].VerificationPolicy = policyWithVerifiers
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}
	_, _, _, profile := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
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
	if got, want := len(proof.Ratifications), majority(len(k.replicas))+3; got < want {
		t.Errorf("expected at least %d sehs, got %d", got, want)
	}
	_, err = coname.VerifyLookup(clientConfig, alice, proof, k.clocks()[0].Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyserverRejectsUnsignedUpdate(t *testing.T) {
	dieOnCtrlC()
	k, policyWithVerifiers, teardown := setupRealm(t, 3, 3)
	defer teardown()
	stop := stoppableSyncedClocks(k.clocks())
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientConfig.Realms[0].VerificationPolicy = policyWithVerifiers
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}
	_, _, aliceEntry, aliceProfile := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	updateC := proto.NewE2EKSPublicClient(conn)

	_, err = updateC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   *aliceEntry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: *aliceProfile,
		LookupParameters: &proto.LookupRequest{
			UserId:            alice,
			QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
		},
	})
	if err == nil {
		t.Fatalf("update went through even though it wasn't signed (and should have been required to be)")
	}
}

func TestKeyserverRejectsMissignedUpdate(t *testing.T) {
	dieOnCtrlC()
	k, policyWithVerifiers, teardown := setupRealm(t, 3, 3)
	defer teardown()
	stop := stoppableSyncedClocks(k.clocks())
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientConfig.Realms[0].VerificationPolicy = policyWithVerifiers
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}
	_, alicePk, aliceEntry, aliceProfile := doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("noncenoncenonceNONCE"),
		Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
	})

	var aliceKeyIdBytes [8]byte
	sha3.ShakeSum256(aliceKeyIdBytes[:], proto.MustMarshal(alicePk))
	aliceKeyid := binary.BigEndian.Uint64(aliceKeyIdBytes[:8])
	_, badSk, _ := ed25519.GenerateKey(rand.Reader)

	conn, err := grpc.Dial(k.replicas[0].pcfg.PublicAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	updateC := proto.NewE2EKSPublicClient(conn)
	_, err = updateC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   *aliceEntry,
			Signatures: map[uint64][]byte{aliceKeyid: ed25519.Sign(badSk, aliceEntry.Encoding)[:]},
		},
		Profile: *aliceProfile,
		LookupParameters: &proto.LookupRequest{
			UserId:            alice,
			QuorumRequirement: clientConfig.Realms[0].VerificationPolicy.GetQuorum(),
		},
	})
	if err == nil {
		t.Fatalf("update went through even though it was signed with the wrong key")
	}
}

func TestKeyserverHKP(t *testing.T) {
	k, policyWithVerifiers, teardown := setupRealm(t, 3, 3)
	defer teardown()
	stop := stoppableSyncedClocks(k.clocks())
	defer close(stop)

	clientConfig, ck := k.setupClient()
	clientConfig.Realms[0].VerificationPolicy = policyWithVerifiers
	clientTLS, err := clientConfig.Realms[0].ClientTLS.Config(ck)
	if err != nil {
		k.t.Fatal(err)
	}

	pgpKeyRef := []byte("this-is-alices-pgp-key")
	doRegister(k, alice, 0, proto.Profile{
		Nonce: []byte("definitely used only once"),
		Keys:  map[string][]byte{"pgp": pgpKeyRef},
	})

	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: clientTLS,
	}}
	url := "https://" + k.replicas[0].pcfg.HKPAddr + "/pks/lookup?op=get&search=" + alice
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
