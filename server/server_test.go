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
	"crypto/rand"
	"crypto/tls"
	"io/ioutil"
	"log"
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
	"github.com/yahoo/coname/server/kv/leveldbkv"
	"github.com/yahoo/coname/server/kv/logkv"
	"github.com/yahoo/coname/server/kv/tracekv"
)

func TestKeyserverStartProgressStop(t *testing.T) {
	dir, err := ioutil.TempDir("", "keyserver")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ldb, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ldb.Close()

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sv := &proto.SignatureVerifier{Threshold: &proto.SignatureVerifier_ThresholdVerifier{
		Threshold: 1,
		Verifiers: []*proto.SignatureVerifier{{Ed25519: pk[:]}},
	}}

	ca, caPool, caKey := tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, ca, caKey, "127.0.0.1", nil)
	cfg := &Config{
		Realm:                "testing",
		RatificationVerifier: sv.Threshold,
		ID:                   common.RatifierID(sv),
		RatificationKey:      sk,

		UpdateAddr:   "localhost:0",
		LookupAddr:   "localhost:0",
		VerifierAddr: "localhost:0",
		UpdateTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		LookupTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		VerifierTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert},

		MinEpochInterval:   0,
		MaxEpochInterval:   0 * time.Millisecond,
		RetryEpochInterval: 1 * time.Millisecond,
	}

	db := leveldbkv.Wrap(ldb)
	if testing.Verbose() {
		db = logkv.WithLogging(db, log.New(os.Stdout, "", log.LstdFlags))
	}

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
	<-progressCh
	ks.Stop()
	ldb.Close()

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