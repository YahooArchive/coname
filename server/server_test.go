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
	"crypto/ecdsa"
	"crypto/rand"
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

func setupKeyserver(t *testing.T) (cfg *Config, db kv.DB, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey, teardown func()) {
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
	sv := &proto.SignatureVerifier{Threshold: &proto.SignatureVerifier_ThresholdVerifier{
		Threshold: 1,
		Verifiers: []*proto.SignatureVerifier{{Ed25519: pk[:]}},
	}}

	caCert, caPool, caKey = tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	cfg = &Config{
		Realm:                testingRealm,
		RatificationVerifier: sv.Threshold,
		ID:                   common.RatifierID(sv) << 32, // mark the keyserver
		RatificationKey:      sk,

		UpdateAddr:   "localhost:0",
		LookupAddr:   "localhost:0",
		VerifierAddr: "localhost:0",
		UpdateTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		LookupTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		VerifierTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert},

		MinEpochInterval:   0,
		MaxEpochInterval:   300 * time.Microsecond,
		RetryEpochInterval: 100 * time.Microsecond,
	}
	db = leveldbkv.Wrap(ldb)
	return
}

func TestKeyserverStartStop(t *testing.T) {
	cfg, db, _, _, _, teardown := setupKeyserver(t)
	defer teardown()
	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()
}

func TestKeyserverStartProgressStop(t *testing.T) {
	cfg, db, _, _, _, teardown := setupKeyserver(t)
	defer teardown()
	// db = logkv.WithDefaultLogging(db)

	// the db writes are test output. We are waiting for epoch 2 to be ratified
	// as a primitive progress check.
	progressCh := make(chan struct{})
	var closeOnce sync.Once
	db = tracekv.WithSimpleTracing(db, func(put tracekv.Put) {
		if len(put.Key) < 1 || put.Key[0] != tableRatificationsPrefix {
			return
		}
		var sr proto.SignedRatification
		sr.Unmarshal(put.Value)
		if sr.Ratification.Epoch == 2 {
			closeOnce.Do(func() { close(progressCh) })
		}
	})

	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()
	<-progressCh
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

func TestKeyserverLookupWithoutQuorumRequirement(t *testing.T) {
	cfg, db, _, caPool, _, teardown := setupKeyserver(t)
	defer teardown()
	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()

	conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSLookupClient(conn)
	proof, err := c.LookupProfile(context.TODO(), &proto.LookupProfileRequest{UserId: alice})
	if err != nil {
		t.Fatal(err)
	}
	if proof.UserId != alice {
		t.Errorf("proof.UserId != \"alice\" (got %q)", proof.UserId)
	}
	if len(proof.IndexProof) != vrf.ProofSize {
		t.Errorf("len(proof.IndexProof) != %d (it is %d)", vrf.ProofSize, len(proof.IndexProof))
	}
}

func TestKeyserverLookupRequireKeyserver(t *testing.T) {
	cfg, db, _, caPool, _, teardown := setupKeyserver(t)
	defer teardown()
	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()

	conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSLookupClient(conn)
	proof, err := c.LookupProfile(context.TODO(), &proto.LookupProfileRequest{
		UserId: alice,
		QuorumRequirement: &proto.QuorumExpr{
			Threshold: 1,
			Verifiers: []uint64{cfg.ID},
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
		t.Errorf("expected 1 ratification, got %d", len(proof.Ratifications))
	}
}

func setupVerifier(t *testing.T, keyserverVerif *proto.SignatureVerifier, keyserverAddr string, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey) (cfg *verifier.Config, db kv.DB, teardown func()) {
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
	sv := &proto.SignatureVerifier{Ed25519: pk[:]}

	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	cfg = &verifier.Config{
		Realm:          testingRealm,
		KeyserverVerif: keyserverVerif,
		KeyserverAddr:  keyserverAddr,

		ID:              common.RatifierID(sv),
		RatificationKey: sk,
		TLS:             &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool},
	}
	db = leveldbkv.Wrap(ldb)
	return
}

func testVerifierStartProgressStop(t *testing.T, progress uint64) {
	cfg, db, caCert, caPool, caKey, serverTeardown := setupKeyserver(t)
	defer serverTeardown()
	// db = logkv.WithDefaultLogging(db)

	vcfgBarrier := make(chan struct{})
	var vcfg *verifier.Config

	// the db writes are test output. We are waiting for epoch 2 to be ratified
	// by the verifier and pushed to the server as a primitive progress check.
	progressCh := make(chan struct{})
	var closeOnce sync.Once
	db = tracekv.WithSimpleTracing(db, func(put tracekv.Put) {
		if len(put.Key) < 1 || put.Key[0] != tableRatificationsPrefix {
			return
		}
		var sr proto.SignedRatification
		sr.Unmarshal(put.Value)
		<-vcfgBarrier
		if sr.Ratification.Epoch == progress && sr.Ratifier == vcfg.ID {
			closeOnce.Do(func() { close(progressCh) })
		}
	})

	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	defer ks.Stop()

	vcfg, vdb, verifierTeardown := setupVerifier(t, &proto.SignatureVerifier{Threshold: cfg.RatificationVerifier}, ks.verifierListen.Addr().String(), caCert, caPool, caKey)
	defer verifierTeardown()
	close(vcfgBarrier)

	vr, err := verifier.Start(vcfg, vdb)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Stop()

	<-progressCh
}

func TestVerifierStartProgress1Stop(t *testing.T) {
	testVerifierStartProgressStop(t, 1)
}
func TestVerifierStartProgress2Stop(t *testing.T) {
	testVerifierStartProgressStop(t, 2)
}
func TestVerifierStartProgress100Stop(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	testVerifierStartProgressStop(t, 100)
}

func setupRealm(t *testing.T, nVerifiers int) (ks *Keyserver, caPool *x509.CertPool, verifiers []uint64, teardown func()) {
	cfg, db, caCert, caPool, caKey, teardown := setupKeyserver(t)

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
			var sr proto.SignedRatification
			sr.Unmarshal(put.Value)
			<-vrBarrier
			if sr.Ratification.Epoch == 1 && sr.Ratifier == vcfg.ID {
				doneOnce.Do(func() { doneVerifiers <- doneVerifier{verifierTeardown, vcfg.ID} })
			}
		})
		go func(i int) {
			var vdb kv.DB
			<-ksBarrier
			vcfg, vdb, verifierTeardown = setupVerifier(t, &proto.SignatureVerifier{Threshold: cfg.RatificationVerifier}, ks.verifierListen.Addr().String(), caCert, caPool, caKey)
			close(vrBarrier)

			_, err := verifier.Start(vcfg, vdb)
			if err != nil {
				t.Fatal(err)
			}
		}(i)
	}
	ks, err := Open(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	close(ksBarrier)
	ks.Start()
	teardown = chain(ks.Stop, teardown)

	for i := 0; i < nVerifiers; i++ {
		v := <-doneVerifiers
		verifiers = append(verifiers, v.id)
		teardown = chain(v.teardown, teardown)
	}
	return ks, caPool, verifiers, teardown
}

func TestKeyserverLookupRequireThreeVerifiers(t *testing.T) {
	ks, caPool, verifiers, teardown := setupRealm(t, 3)
	defer teardown()

	conn, err := grpc.Dial(ks.lookupListen.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		t.Fatal(err)
	}
	c := proto.NewE2EKSLookupClient(conn)
	proof, err := c.LookupProfile(context.TODO(), &proto.LookupProfileRequest{
		UserId: alice,
		QuorumRequirement: &proto.QuorumExpr{
			Threshold: uint32(len(verifiers)),
			Verifiers: verifiers,
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
		t.Errorf("expected %d ratifications, got %d", len(verifiers), len(proof.Ratifications))
	}
	lastEpoch := uint64(0)
	for i, r := range proof.Ratifications {
		if lastEpoch > r.Ratification.Epoch {
			t.Errorf("proof.Ratifications[%d].Ratification.Epoch > proof.Ratifications[%d].Ratification.Epoch (%d > %d), but the list is supposed to be oldest-first", i-1, i, lastEpoch, r.Ratification.Epoch)
		}
		lastEpoch = r.Ratification.Epoch
	}
}
