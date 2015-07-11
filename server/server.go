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
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/replication"
	"github.com/yahoo/coname/server/replication/kvlog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config encapsulates everything that needs to be specified about a single
// replica of one realm's keyserver to operate it.
// TODO: make this a protobuf, Unmarshal from JSON
type Config struct {
	Realm string

	ID                   uint64
	RatificationVerifier *proto.SignatureVerifier_ThresholdVerifier
	RatificationKey      *[ed25519.PrivateKeySize]byte // [32]byte: secret; [32]byte: public

	UpdateAddr, LookupAddr, VerifierAddr string
	UpdateTLS, LookupTLS, VerifierTLS    *tls.Config

	MinEpochInterval, MaxEpochInterval, RetryEpochInterval time.Duration
	// FIXME: tls.Config is not serializable, replicate relevant fields
}

// Keyserver either manages or verifies a single end-to-end keyserver realm.
type Keyserver struct {
	realm                string
	ratificationVerifier *proto.SignatureVerifier_ThresholdVerifier
	id                   uint64

	thresholdSigningIndex uint32
	ratificationKey       *[ed25519.PrivateKeySize]byte

	db  kv.DB
	log replication.LogReplicator
	proto.ReplicaState

	updateServer, lookupServer, verifierServer *grpc.Server
	updateListen, lookupListen, verifierListen net.Listener

	minEpochInterval, maxEpochInterval, retryEpochInterval time.Duration

	// state used for determining whether we should start a new epoch.
	// see replication.proto for explanation.
	leaderHint, canEpoch, mustEpoch       bool
	leaderHintSet                         <-chan bool
	canEpochSet, mustEpochSet, retryEpoch *time.Timer
	// proto.ReplicaState.PendingUpdates is used as well

	stop     chan struct{}
	waitStop sync.WaitGroup
}

// Open initializes a new keyserver based on cfg, reads the persistent state and
// binds to the specified ports. It does not handle input: requests will block.
func Open(cfg *Config, db kv.DB) (ks *Keyserver, err error) {
	log, err := kvlog.New(db, []byte{tableReplicationLogPrefix})
	if err != nil {
		return nil, err
	}

	ks = &Keyserver{
		realm:                cfg.Realm,
		id:                   cfg.ID,
		ratificationVerifier: cfg.RatificationVerifier,
		ratificationKey:      cfg.RatificationKey,
		minEpochInterval:     cfg.MinEpochInterval,
		maxEpochInterval:     cfg.MaxEpochInterval,
		retryEpochInterval:   cfg.RetryEpochInterval,
		db:                   db,
		log:                  log,
		stop:                 make(chan struct{}),

		// TODO: change when using actual replication
		leaderHint:    true,
		leaderHintSet: nil,

		canEpochSet:  time.NewTimer(0),
		mustEpochSet: time.NewTimer(0),
		retryEpoch:   time.NewTimer(0),
	}

	switch replicaStateBytes, err := db.Get(tableReplicaState); err {
	case ks.db.ErrNotFound():
		// ReplicaState zero value is valid initialization
	case nil:
		if err := ks.ReplicaState.Unmarshal(replicaStateBytes); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if cfg.UpdateAddr != "" {
		ks.updateServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.UpdateTLS)))
		proto.RegisterE2EKSUpdateServer(ks.updateServer, ks)
		ks.updateListen, err = net.Listen("tcp", cfg.UpdateAddr)
		if err != nil {
			return nil, err
		}
	}
	if cfg.LookupAddr != "" {
		ks.lookupServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.LookupTLS)))
		proto.RegisterE2EKSLookupServer(ks.lookupServer, ks)
		ks.lookupListen, err = net.Listen("tcp", cfg.LookupAddr)
		if err != nil {
			ks.updateListen.Close()
			return nil, err
		}
	}
	if cfg.VerifierAddr != "" {
		ks.verifierServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.VerifierTLS)))
		ks.verifierListen, err = net.Listen("tcp", cfg.VerifierAddr)
		if err != nil {
			ks.updateListen.Close()
			ks.lookupListen.Close()
			return nil, err
		}
	}
	return ks, nil
}

/// Start makes the keyserver start handling requests (forks goroutines).
func (ks *Keyserver) Start() {
	ks.log.Start(ks.NextIndexLog)
	if ks.updateServer != nil {
		go ks.updateServer.Serve(ks.updateListen)
	}
	if ks.lookupServer != nil {
		go ks.lookupServer.Serve(ks.lookupListen)
	}
	if ks.verifierServer != nil {
		go ks.verifierServer.Serve(ks.verifierListen)
	}
	ks.resetEpochTimers(ks.LastEpochDelimiter.Timestamp.Time())
	ks.waitStop.Add(1)
	go func() { ks.run(); ks.waitStop.Done() }()
}

/// Stop cleanly shuts down the keyserver and then returns.
// TODO: figure out what will happen to connected clients?
func (ks *Keyserver) Stop() {
	if ks.updateServer != nil {
		ks.updateServer.Stop()
	}
	if ks.lookupServer != nil {
		ks.lookupServer.Stop()
	}
	if ks.verifierServer != nil {
		ks.verifierServer.Stop()
	}
	close(ks.stop)
	ks.waitStop.Wait()
	ks.canEpochSet.Stop()
	ks.mustEpochSet.Stop()
	ks.retryEpoch.Stop()
	ks.log.Stop()
}

// run is the CSP-style main loop of the keyserver. All code critical for safe
// persistence should be directly in run. All functions called from run should
// either interpret data and modify their mutable arguments OR interact with the
// network and disk, but not both.
func (ks *Keyserver) run() {
	var step proto.KeyserverStep
	wb := ks.db.NewBatch()
	for {
		select {
		case <-ks.stop:
			return
		case stepBytes := <-ks.log.WaitCommitted():
			if stepBytes == nil {
				continue // allow logs to skip slots for indexing purposes
			}
			if err := step.Unmarshal(stepBytes); err != nil {
				log.Panicf("invalid step pb in replicated log: %s", err)
			}
			ks.NextIndexLog++
			ks.step(&step, &ks.ReplicaState, wb)
			wb.Put(tableReplicaState, proto.MustMarshal(&ks.ReplicaState))
			if err := ks.db.Write(wb); err != nil {
				log.Panicf("sync step to db: %s", err)
			}
			wb.Reset()
			step.Reset()
			// TODO: if we handled a client connected directly to us, reply
		case ks.leaderHint = <-ks.leaderHintSet:
			ks.maybeEpoch()
		case <-ks.canEpochSet.C:
			ks.canEpoch = true
			ks.maybeEpoch()
		case <-ks.mustEpochSet.C:
			ks.mustEpoch = true
			ks.maybeEpoch()
		case <-ks.retryEpoch.C:
			ks.maybeEpoch()
		}
		// TODO: case pushRatification
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (ks *Keyserver) step(step *proto.KeyserverStep, rs *proto.ReplicaState, wb kv.Batch) {
	// ks: &const
	// step, rs, wb: &mut
	switch {
	case step.Update != nil:
		if err := common.VerifyUpdate( /*TODO: tree lookup*/ nil, step.Update); err != nil {
			// TODO: return the client-bound error code
			return
		}
		// TODO: set entry in tree
		// TODO: update verifier log index structure
		// TODO: figure out how to do epoch delimiter timers
		rs.PendingUpdates = true
	case step.EpochDelimiter != nil:
		if step.EpochDelimiter.EpochNumber <= rs.LastEpochDelimiter.EpochNumber {
			return // a duplicate of this step has already been handled
		}
		rs.LastEpochDelimiter = *step.EpochDelimiter
		rs.PendingUpdates = false
		ks.resetEpochTimers(ks.LastEpochDelimiter.Timestamp.Time())
		ratification := &proto.SignedRatification{
			Ratifier: ks.id,
			Ratification: proto.SignedRatification_RatificationT_PreserveEncoding{proto.SignedRatification_RatificationT{
				Realm: ks.realm,
				Epoch: step.EpochDelimiter.EpochNumber,
				Summary: proto.SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding{proto.SignedRatification_RatificationT_KeyserverStateSummary{
					RootHash:            nil, // TODO: merklemap.GetRootHash()
					PreviousSummaryHash: nil, // TODO: rs.PreviousSummaryHash, and update it
				}, nil},
				Timestamp: step.EpochDelimiter.Timestamp,
			}, nil},
		}
		ratification.Ratification.Summary.UpdateEncoding()
		ratification.Ratification.UpdateEncoding()
		ratification.Signature = proto.MustMarshal(&proto.ThresholdSignature{
			KeyIndex:  []uint32{ks.thresholdSigningIndex},
			Signature: [][]byte{ed25519.Sign(ks.ratificationKey, proto.MustMarshal(&ratification.Ratification))[:]},
		})
		ks.log.Propose(context.TODO(), proto.MustMarshal(&proto.KeyserverStep{ReplicaRatification: ratification}))
		// TODO: Propose may fail silently when replicas crash. We want to
		// keep retrying ReplicaRatifications because if not enough of
		// them go in, the epoch will not be properly signed. Note that it
		// is okay to create new epochs while we dont have signatures for the
		// last one, but we must eventually sign all of them, otherwise
		// verifiers will block indefinitely. It may or may not be worth
		// unifying this with epoch delimiter retry logic -- we need one epoch
		// delimiter per cluster but a majority of replicas need to sign.
	case step.ReplicaRatification != nil:
		rNew := step.ReplicaRatification
		dbkey := tableRatifications(rNew.Ratification.Epoch, rNew.Ratifier)
		switch rExistingBytes, err := ks.db.Get(dbkey); err {
		case nil:
			rExisting := new(proto.SignedRatification)
			if err := rExisting.Unmarshal(rExistingBytes); err != nil {
				log.Panicf("tableRatifications(%d, %d) invalid (this is our ID!): %s", rNew.Ratification.Epoch, rNew.Ratifier, err)
			}
			sigNew := new(proto.ThresholdSignature)
			if err := sigNew.Unmarshal(rExisting.Signature); err != nil {
				log.Panicf("log[%d].step.ReplicaRatification.Signature invalid protobuf: %s", ks.ReplicaState.NextIndexLog-1, err)
			}
			sigExisting := new(proto.ThresholdSignature)
			if err := sigExisting.Unmarshal(rExisting.Signature); err != nil {
				log.Panicf("tableRatifications(%d, %d).Signature invalid protobuf (this is our ID!): %s", rExisting.Ratification.Epoch, rExisting.Ratifier, err)
			}
			common.MergeThresholdSignatures(sigExisting, sigNew)
			rExisting.Signature = proto.MustMarshal(sigExisting)
			wb.Put(dbkey, proto.MustMarshal(rExisting))
		case ks.db.ErrNotFound():
			wb.Put(dbkey, proto.MustMarshal(rNew))
		default:
			log.Panicf("db.Get(tableRatifications(%d, %d)) failed: %s", rNew.Ratification.Epoch, rNew.Ratifier, err)
		}
	case step.VerifierRatification != nil:
		rNew := step.VerifierRatification
		// TODO: only valid ratifications should get here. re-validate anyway?
		// TODO: should we check if there already is a ratification? Then what?
		dbkey := tableRatifications(rNew.Ratification.Epoch, rNew.Ratifier)
		wb.Put(dbkey, proto.MustMarshal(rNew))
	default:
		log.Panicf("unknown step pb in replicated log: %#v", step)
	}
}

// shouldEpoch returns true if this node should append an epoch delimiter to the
// log. see replication.proto for details.
func (ks *Keyserver) shouldEpoch() bool {
	return ks.leaderHint && (ks.mustEpoch || ks.canEpoch && ks.ReplicaState.PendingUpdates)
}

// maybeEpoch proposes an epoch delimiter for inclusion in the log if necessary.
func (ks *Keyserver) maybeEpoch() {
	if !ks.shouldEpoch() {
		return
	}
	ks.log.Propose(context.TODO(), proto.MustMarshal(&proto.KeyserverStep{EpochDelimiter: &proto.EpochDelimiter{
		EpochNumber: ks.LastEpochDelimiter.EpochNumber + 1,
		Timestamp:   proto.Time(time.Now()),
	}}))
	ks.canEpochSet.Stop()
	ks.mustEpochSet.Stop()
	ks.retryEpoch.Reset(ks.retryEpochInterval)
}

func (ks *Keyserver) resetEpochTimers(t time.Time) {
	ks.canEpochSet.Reset(t.Add(ks.minEpochInterval).Sub(time.Now()))
	ks.mustEpochSet.Reset(t.Add(ks.maxEpochInterval).Sub(time.Now()))
	ks.retryEpoch.Stop()
	ks.canEpoch = false
	ks.mustEpoch = false
}
