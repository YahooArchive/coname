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

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/tlstestutil"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/kv/leveldbkv"
	"github.com/yahoo/coname/server/kv/tracekv"
	"github.com/yahoo/coname/verifier"
)

const (
	testingRealm = "testing"
)

func chain(fs ...func()) func() {
	ret := func() {}
	for _, f := range fs {
		// f is copied to the heap, the closure refers to a unique copy of its own
		f = func() { ret(); f() }
	}
	return ret
}

func setupKeyserver(t *testing.T) (cfg *Config, db kv.DB, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey, teardown func()) {
	dir, err := ioutil.TempDir("", "keyserver")
	if err != nil {
		t.Fatal(err)
	}
	teardown = chain(func() { os.RemoveAll(dir) }, teardown)
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
		ID:                   common.RatifierID(sv),
		RatificationKey:      sk,

		UpdateAddr:   "localhost:0",
		LookupAddr:   "localhost:0",
		VerifierAddr: "localhost:0",
		UpdateTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		LookupTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		VerifierTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert},
		//VerifierTLS: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ClientCAs: caPool, ClientAuth: tls.RequireAnyClientCert},

		MinEpochInterval:   0,
		MaxEpochInterval:   0 * time.Millisecond,
		RetryEpochInterval: 1 * time.Millisecond,
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

func setupVerifier(t *testing.T, keyserverVerif *proto.SignatureVerifier, keyserverAddr string, caCert *x509.Certificate, caPool *x509.CertPool, caKey *ecdsa.PrivateKey) (cfg *verifier.Config, db kv.DB, teardown func()) {
	dir, err := ioutil.TempDir("", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	teardown = chain(func() { os.RemoveAll(dir) }, teardown)
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

func TestVerifierStartProgressStop(t *testing.T) {
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
		if sr.Ratification.Epoch == 2 && sr.Ratifier == vcfg.ID {
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
