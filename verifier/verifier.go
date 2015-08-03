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

package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config encapsulates everything that needs to be specified about a verifer.
// TODO: make this a protobuf, Unmarshal from JSON
type Config struct {
	Realm          string
	KeyserverVerif *proto.AuthorizationPolicy
	KeyserverAddr  string

	ID              uint64
	RatificationKey *[ed25519.PrivateKeySize]byte // [32]byte: secret; [32]byte: public
	TLS             *tls.Config                   // FIXME: tls.Config is not serializable, replicate relevant fields
}

// Verifier verifies that the Keyserver of the realm is not cheating.
// The veirifier is not replicated because one can just run several.
type Verifier struct {
	realm          string
	keyserverVerif *proto.AuthorizationPolicy
	keyserverAddr  string
	auth           credentials.TransportAuthenticator

	id              uint64
	ratificationKey *[ed25519.PrivateKeySize]byte

	db kv.DB
	vs proto.VerifierState

	keyserver proto.E2EKSVerificationClient

	stopOnce sync.Once
	stop     chan struct{}
	waitStop sync.WaitGroup
}

// Start initializes a new verifier based on config and db, or returns an error
// if initialization fails. It then starts the worker goroutine(s).
func Start(cfg *Config, db kv.DB) (*Verifier, error) {
	vr := &Verifier{
		realm:          cfg.Realm,
		keyserverVerif: cfg.KeyserverVerif,
		keyserverAddr:  cfg.KeyserverAddr,
		auth:           credentials.NewTLS(cfg.TLS),

		id:              cfg.ID,
		ratificationKey: cfg.RatificationKey,

		db: db,

		stop: make(chan struct{}),
	}

	switch verifierStateBytes, err := db.Get(tableVerifierState); err {
	case vr.db.ErrNotFound():
		vr.vs.NextEpoch = 1
	case nil:
		if err := vr.vs.Unmarshal(verifierStateBytes); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	vr.waitStop.Add(1)
	go func() { vr.run(); vr.waitStop.Done() }()
	return vr, nil
}

// Stop cleanly shuts down the verifier and then returns.
func (vr *Verifier) Stop() {
	vr.stopOnce.Do(func() {
		close(vr.stop)
		vr.waitStop.Wait()
	})
}

func (vr *Verifier) shuttingDown() bool {
	select {
	case <-vr.stop:
		return true
	default:
		return false
	}
}

// run is the CSP-style main loop of the verifier. All code critical for safe
// persistence should be directly in run. All functions called from run should
// either interpret data and modify their mutable arguments OR interact with the
// network and disk, but not both.
func (vr *Verifier) run() {
	for !vr.shuttingDown() {
		keyserverConnection, err := grpc.Dial(vr.keyserverAddr, grpc.WithTimeout(time.Second), grpc.WithTransportCredentials(vr.auth))
		if err != nil {
			log.Printf("dial %s: %s", vr.keyserverAddr, err)
			continue
		}
		vr.keyserver = proto.NewE2EKSVerificationClient(keyserverConnection)
		stream, err := vr.keyserver.VerifierStream(context.TODO(), &proto.VerifierStreamRequest{
			Start:    vr.vs.NextIndex,
			PageSize: math.MaxUint64,
		})
		if err != nil {
			keyserverConnection.Close()
			log.Printf("VerifierStream: %s", err)
			continue
		}

		wb := vr.db.NewBatch()
		for !vr.shuttingDown() {
			var step *proto.VerifierStep
			step, err = stream.Recv()
			if err != nil {
				log.Printf("VerifierStream.Recv: %s", err)
				break
			}
			wb.Put(tableVerifierLog(vr.vs.NextIndex), proto.MustMarshal(step))
			deferredIO := vr.step(step, &vr.vs, wb)
			vr.vs.NextIndex++
			if deferredIO != nil {
				wb.Put(tableVerifierState, proto.MustMarshal(&vr.vs))
				if err := vr.db.Write(wb); err != nil {
					log.Panicf("sync step to db: %s", err)
				}
				wb.Reset()
				deferredIO()
			}
		}
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (vr *Verifier) step(step *proto.VerifierStep, vs *proto.VerifierState, wb kv.Batch) (deferredIO func()) {
	// vr: &const
	// step, vs, wb: &mut
	switch {
	case step.Update != nil:
		if err := common.VerifyUpdate( /*TODO(dmz): tree lookup*/ nil, step.Update); err != nil {
			return // TODO: decide whether keyserver should guarantee that verifiers don't see bad updates
		}
		// TODO(dmz): set entry in tree
	case step.Epoch != nil:
		ok := common.VerifyPolicy(
			vr.keyserverVerif,
			step.Epoch.Head.PreservedEncoding,
			step.Epoch.Signatures)
		// the bad steps here will not get persisted to disk right now. do we want them to?
		if !ok {
			log.Fatalf("%d: keyserver signature verification failed: %#v", vs.NextIndex, *step)
		}
		r := step.Epoch.Head
		if r.Head.Realm != vr.realm {
			log.Fatalf("%d: seh for realm %q, expected %q: %#v", vr.vs.NextEpoch, r.Head.Realm, vr.realm, *step)
		}
		if r.Head.Epoch != vr.vs.NextEpoch {
			log.Fatalf("%d: got epoch %d instead: %#v", vr.vs.NextEpoch, r.Head.Epoch, *step)
		}
		s := &r.Head
		if !bytes.Equal(s.PreviousSummaryHash, vr.vs.PreviousSummaryHash) {
			log.Fatalf("%d: seh with previous summary hash %q, expected %q: %#v", vr.vs.NextEpoch, s.PreviousSummaryHash, vr.vs.PreviousSummaryHash, *step)
		}
		if s.RootHash != nil /*TODO(dmz): merkletree.GetRootHash()*/ {
			log.Fatalf("%d: seh with root hash %q, expected nil: %#v", vr.vs.NextEpoch, s.RootHash /*, TODO*/, *step)
		}
		seh := &proto.SignedEpochHead{
			Head: proto.TimestampedEpochHead_PreserveEncoding{proto.TimestampedEpochHead{
				Head: proto.EpochHead_PreserveEncoding{proto.EpochHead{
					RootHash:            nil, // TODO(dmz): merklemap.GetRootHash()
					PreviousSummaryHash: vr.vs.PreviousSummaryHash,
					Realm:               vr.realm,
					Epoch:               vr.vs.NextEpoch,
				}, nil},
				Timestamp: proto.Time(time.Now()),
			}, nil},
			Signatures: make(map[uint64][]byte, 1),
		}
		seh.Head.Head.UpdateEncoding()
		h := sha256.Sum256(seh.Head.Head.PreservedEncoding)
		vr.vs.PreviousSummaryHash = h[:]
		seh.Head.UpdateEncoding()
		seh.Signatures[vr.id] = ed25519.Sign(vr.ratificationKey, proto.MustMarshal(&seh.Head))[:]
		wb.Put(tableRatifications(vr.vs.NextEpoch, vr.id), proto.MustMarshal(seh))
		vs.NextEpoch++
		return func() {
			_, err := vr.keyserver.PushRatification(context.TODO(), seh)
			if err != nil { // TODO: how should this error be handled (grpc issue #238 may be relevant)
				log.Printf("PushRatification: %s", err)
			}
		}
	default:
		log.Fatalf("%d: unknown step: %#v", vs.NextIndex, *step)
	}
	return
}
