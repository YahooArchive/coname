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
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/andres-erbsen/tlstestutil"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/common/vrf"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/kv/leveldbkv"
	"github.com/yahoo/coname/server/kv/tracekv"
	"github.com/yahoo/coname/verifier"
)

const (
	testingRealm = "testing"
	alice        = "alice"
	tick         = time.Second
	poll         = 100 * time.Microsecond
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

// setupKeyserver initializes a keyserver, but does not start it and does not
// wait for it to sign anything.
func setupKeyserver(t *testing.T) (cfg *Config, db kv.DB, pol *proto.AuthorizationPolicy, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey, teardown func()) {
	dir, err := ioutil.TempDir("", "keyserver")
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
	pked := &proto.PublicKey{Ed25519: pk[:]}
	replicaID := common.KeyID(pked)
	pol = &proto.AuthorizationPolicy{
		PublicKeys: map[uint64]*proto.PublicKey{replicaID: pked},
		Quorum:     &proto.QuorumExpr{Threshold: 1, Candidates: []uint64{replicaID}},
	}

	_, vrfSecret, err := vrf.GenerateKey(rand.Reader)
	if err != nil {
		teardown()
		t.Fatal(err)
	}

	caCert, caPool, caKey = tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	cfg = &Config{
		Realm:           testingRealm,
		ServerID:        replicaID,
		ReplicaID:       replicaID,
		RatificationKey: sk,
		VRFSecret:       vrfSecret,

		UpdateAddr:   "localhost:0",
		LookupAddr:   "localhost:0",
		VerifierAddr: "localhost:0",
		UpdateTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		LookupTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		VerifierTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert},

		MinEpochInterval:   tick,
		MaxEpochInterval:   tick,
		RetryEpochInterval: poll,
	}
	db = leveldbkv.Wrap(ldb)
	return
}

func TestKeyserverStartStop(t *testing.T) {
	cfg, db, _, _, _, _, teardown := setupKeyserver(t)
	defer teardown()
	ks, err := Open(cfg, db, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()
}

func TestKeyserverStartProgressStop(t *testing.T) {
	cfg, db, _, _, _, _, teardown := setupKeyserver(t)
	defer teardown()
	// db = logkv.WithDefaultLogging(db)

	// the db writes are test output. We are waiting for epoch 5 to be ratified
	// as a primitive progress check.
	progressCh := make(chan struct{})
	var closeOnce sync.Once
	db = tracekv.WithSimpleTracing(db, func(put tracekv.Put) {
		if len(put.Key) < 1 || put.Key[0] != tableRatificationsPrefix {
			return
		}
		var sr proto.SignedEpochHead
		sr.Unmarshal(put.Value)
		if sr.Head.Head.Epoch == 3 {
			closeOnce.Do(func() { close(progressCh) })
		}
	})

	clk := clock.NewMock()
	ks, err := Open(cfg, db, clk)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()

loop:
	for {
		select {
		case <-progressCh:
			break loop
		case <-time.After(poll):
			clk.Add(tick)
			runtime.Gosched()
		}
	}

	ks.Stop()
	teardown()

	if testing.Verbose() {
		time.Sleep(time.Millisecond)
		n := runtime.NumGoroutine()
		stackBuf := make([]byte, 1014)
		var l int
		for l = runtime.Stack(stackBuf, true); l == len(stackBuf) && l < 128*1024; {
			stackBuf = append(stackBuf, stackBuf...)
		}
		t.Logf("%d goroutines in existance after Stop:\n%s", n, stackBuf[:l])
	}
}

func withServer(func(*testing.T, *Keyserver)) {
}

func doUpdate(t *testing.T, ks *Keyserver, caPool *x509.CertPool, name string, profileContents proto.Profile) *proto.Profile_PreserveEncoding {
	conn, err := grpc.Dial(ks.updateListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	profile := proto.Profile_PreserveEncoding{
		Profile: profileContents,
	}
	profile.UpdateEncoding()
	h := sha256.Sum256(profile.PreservedEncoding)
	entry := proto.Entry_PreserveEncoding{
		Entry: proto.Entry{
			Index:   vrf.Compute([]byte(name), ks.vrfSecret),
			Version: 0,
			UpdatePolicy: &proto.AuthorizationPolicy{
				PublicKeys: make(map[uint64]*proto.PublicKey),
				Quorum: &proto.QuorumExpr{
					Threshold:      0,
					Candidates:     []uint64{},
					Subexpressions: []*proto.QuorumExpr{},
				},
			},
			ProfileHash: h[:],
		},
	}
	entry.UpdateEncoding()
	updateC := proto.NewE2EKSUpdateClient(conn)
	proof, err := updateC.Update(context.TODO(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile:          profile,
		LookupParameters: &proto.LookupRequest{UserId: name},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.UserId != name {
		t.Errorf("proof.UserId != \"%q\" (got %q)", name, proof.UserId)
	}
	if len(proof.IndexProof) != vrf.ProofSize {
		t.Errorf("len(proof.IndexProof) != %d (it is %d)", vrf.ProofSize, len(proof.IndexProof))
	}
	if got, want := proof.Profile.PreservedEncoding, profile.PreservedEncoding; !bytes.Equal(got, want) {
		t.Errorf("profile didn't roundtrip: %x != %x", got, want)
	}
	return &profile
}

func runWhileTicking(clk *clock.Mock, f func()) {
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
loop:
	for {
		select {
		case <-time.After(poll):
			clk.Add(tick)
		case <-done:
			break loop
		}
	}
}

func TestKeyserverRoundtripWithoutQuorumRequirement(t *testing.T) {
	cfg, db, _, _, caPool, _, teardown := setupKeyserver(t)
	defer teardown()
	clk := clock.NewMock()
	ks, err := Open(cfg, db, clk)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()

	runWhileTicking(clk, func() {
		profile := doUpdate(t, ks, caPool, alice, proto.Profile{
			Nonce: []byte("noncenoncenonceNONCE"),
			Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
		})

		conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
		if err != nil {
			t.Fatal(err)
		}
		c := proto.NewE2EKSLookupClient(conn)
		proof, err := c.Lookup(context.TODO(), &proto.LookupRequest{UserId: alice})
		if err != nil {
			t.Fatal(err)
		}
		if proof.UserId != alice {
			t.Errorf("proof.UserId != \"alice\" (got %q)", proof.UserId)
		}
		if len(proof.IndexProof) != vrf.ProofSize {
			t.Errorf("len(proof.IndexProof) != %d (it is %d)", vrf.ProofSize, len(proof.IndexProof))
		}
		if got, want := proof.Profile.PreservedEncoding, profile.PreservedEncoding; !bytes.Equal(got, want) {
			t.Errorf("profile didn't roundtrip: %x != %x", got, want)
		}
	})
}

func TestKeyserverUpdateWithoutQuorumRequirement(t *testing.T) {
	cfg, db, _, _, caPool, _, teardown := setupKeyserver(t)
	defer teardown()
	clk := clock.NewMock()
	ks, err := Open(cfg, db, clk)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()

	runWhileTicking(clk, func() {
		doUpdate(t, ks, caPool, alice, proto.Profile{
			Nonce: []byte("noncenoncenonceNONCE"),
			Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
		})

		doUpdate(t, ks, caPool, alice, proto.Profile{
			Nonce: []byte("XYZNONCE"),
			Keys:  map[string][]byte{"abc": []byte{4, 5, 6}, "qwop": []byte("TEST MOOOO")},
		})
	})
}

// setupVerifier initializes a verifier, but does not start it and does not
// wait for it to sign anything.
func setupVerifier(t *testing.T, keyserverVerif *proto.AuthorizationPolicy, keyserverAddr string, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey) (cfg *verifier.Config, db kv.DB, teardown func()) {
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
	sv := &proto.PublicKey{Ed25519: pk[:]}

	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	cfg = &verifier.Config{
		Realm:          testingRealm,
		KeyserverAddr:  keyserverAddr,
		KeyserverVerif: keyserverVerif,

		ID:              common.KeyID(sv),
		RatificationKey: sk,
		TLS:             &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool},
	}
	db = leveldbkv.Wrap(ldb)
	return
}

// setupRealm initializes one keyserver and nVerifiers verifiers, and then
// waits until each one of them has signed an epoch.
func setupRealm(t *testing.T, nVerifiers int) (ks *Keyserver, caPool *x509.CertPool, clk *clock.Mock, verifiers []uint64, teardown func()) {
	cfg, db, pol, caCert, caPool, caKey, teardown := setupKeyserver(t)
	ksDone := make(chan struct{})
	var ksDoneOnce sync.Once
	db = tracekv.WithSimpleTracing(db, func(put tracekv.Put) {
		// We are waiting for an epoch to be ratified (in case there are no
		// verifiers, blocking on them does not help).
		if len(put.Key) < 1 || put.Key[0] != tableRatificationsPrefix {
			return
		}
		ksDoneOnce.Do(func() { close(ksDone) })
	})

	type doneVerifier struct {
		teardown func()
		id       uint64
	}
	ksBarrier := make(chan struct{})
	doneVerifiers := make(chan doneVerifier, nVerifiers)
	for i := 0; i < nVerifiers; i++ {
		vrBarrier := make(chan struct{})
		var verifierTeardown func()
		var vcfg *verifier.Config
		var doneOnce sync.Once
		db = tracekv.WithSimpleTracing(db, func(put tracekv.Put) {
			// We are waiting for epoch 1 to be ratified by the verifier and
			// reach the client because before that lookups requiring this
			// verifier will immediately fail.
			if len(put.Key) < 1 || put.Key[0] != tableRatificationsPrefix {
				return
			}
			var sr proto.SignedEpochHead
			sr.Unmarshal(put.Value)
			<-vrBarrier
			if _, s := sr.Signatures[vcfg.ID]; s && sr.Head.Head.Epoch == 1 {
				doneOnce.Do(func() { doneVerifiers <- doneVerifier{verifierTeardown, vcfg.ID} })
			}
		})
		go func(i int) {
			var vdb kv.DB
			<-ksBarrier
			vcfg, vdb, verifierTeardown = setupVerifier(t, pol, ks.verifierListen.Addr().String(), caCert, caPool, caKey)
			close(vrBarrier)

			_, err := verifier.Start(vcfg, vdb)
			if err != nil {
				t.Fatal(err)
			}
		}(i)
	}
	clk = clock.NewMock()
	ks, err := Open(cfg, db, clk)
	if err != nil {
		t.Fatal(err)
	}
	close(ksBarrier)
	ks.Start()
	teardown = chain(ks.Stop, teardown)

loop:
	for {
		select {
		case <-time.After(poll):
			clk.Add(tick)
		case <-ksDone:
			break loop
		}
	}
	for i := 0; i < nVerifiers; i++ {
		v := <-doneVerifiers
		verifiers = append(verifiers, v.id)
		teardown = chain(v.teardown, teardown)
	}
	return ks, caPool, clk, verifiers, teardown
}

func TestKeyserverLookupRequireKeyserver(t *testing.T) {
	ks, caPool, _, _, teardown := setupRealm(t, 0)
	defer teardown()

	conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSLookupClient(conn)
	proof, err := c.Lookup(context.TODO(), &proto.LookupRequest{
		UserId: alice,
		QuorumRequirement: &proto.QuorumExpr{
			Threshold:  1,
			Candidates: []uint64{ks.serverID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.UserId != alice {
		t.Errorf("proof.UserId != \"alice\" (got %q)", proof.UserId)
	}
	if len(proof.IndexProof) != vrf.ProofSize {
		t.Errorf("len(proof.IndexProof) != %d (it is %d)", vrf.ProofSize, len(proof.IndexProof))
	}
	if len(proof.Ratifications) < 1 {
		t.Errorf("expected 1 seh, got %d", len(proof.Ratifications))
	}
}

func TestKeyserverLookupRequireThreeVerifiers(t *testing.T) {
	ks, caPool, _, verifiers, teardown := setupRealm(t, 3)
	defer teardown()

	conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSLookupClient(conn)
	proof, err := c.Lookup(context.TODO(), &proto.LookupRequest{
		UserId: alice,
		QuorumRequirement: &proto.QuorumExpr{
			Threshold:  uint32(len(verifiers)),
			Candidates: verifiers,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.UserId != alice {
		t.Errorf("proof.UserId != \"alice\" (got %q)", proof.UserId)
	}
	if len(proof.IndexProof) != vrf.ProofSize {
		t.Errorf("len(proof.IndexProof) != %d (it is %d)", vrf.ProofSize, len(proof.IndexProof))
	}
	if len(proof.Ratifications) < len(verifiers) {
		t.Errorf("expected %d sehs, got %d", len(verifiers), len(proof.Ratifications))
	}
	lastEpoch := uint64(0)
	for i, r := range proof.Ratifications {
		if lastEpoch > r.Head.Head.Epoch {
			t.Errorf("proof.Head.Heads[%d].Ratification.Epoch > proof.Ratifications[%d].Ratification.Epoch (%d > %d), but the list is supposed to be oldest-first", i-1, i, lastEpoch, r.Head.Head.Epoch)
		}
		lastEpoch = r.Head.Head.Epoch
	}
}
