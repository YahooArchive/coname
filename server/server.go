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
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/common/vrf"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/merkletree"
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

	ServerID, ReplicaID uint64
	RatificationKey     *[ed25519.PrivateKeySize]byte // [32]byte: secret; [32]byte: public
	VRFSecret           *[vrf.SecretKeySize]byte

	UpdateAddr, LookupAddr, VerifierAddr string
	UpdateTLS, LookupTLS, VerifierTLS    *tls.Config

	MinEpochInterval, MaxEpochInterval, RetryEpochInterval time.Duration
	// FIXME: tls.Config is not serializable, replicate relevant fields

	TreeNonce []byte
}

// Keyserver manages a single end-to-end keyserver realm.
type Keyserver struct {
	realm               string
	serverID, replicaID uint64

	thresholdSigningIndex uint32
	sehKey                *[ed25519.PrivateKeySize]byte
	vrfSecret             *[vrf.SecretKeySize]byte

	db  kv.DB
	log replication.LogReplicator
	rs  proto.ReplicaState

	updateServer, lookupServer, verifierServer *grpc.Server
	updateListen, lookupListen, verifierListen net.Listener

	minEpochInterval, maxEpochInterval, retryEpochInterval time.Duration

	clk clock.Clock
	// state used for determining whether we should start a new epoch.
	// see replication.proto for explanation.
	leaderHint, canEpoch, mustEpoch       bool
	leaderHintSet                         <-chan bool
	canEpochSet, mustEpochSet, retryEpoch *clock.Timer
	// rs.PendingUpdates is used as well

	vmb *VerifierBroadcast
	wr  *WaitingRoom

	stopOnce sync.Once
	stop     chan struct{}
	waitStop sync.WaitGroup

	merkletree *merkletree.MerkleTree
	latestTree *merkletree.NewSnapshot
}

// Open initializes a new keyserver based on cfg, reads the persistent state and
// binds to the specified ports. It does not handle input: requests will block.
func Open(cfg *Config, db kv.DB, clk clock.Clock) (ks *Keyserver, err error) {
	log, err := kvlog.New(db, []byte{tableReplicationLogPrefix})
	if err != nil {
		return nil, err
	}

	ks = &Keyserver{
		realm:              cfg.Realm,
		serverID:           cfg.ServerID,
		replicaID:          cfg.ReplicaID,
		sehKey:             cfg.RatificationKey,
		vrfSecret:          cfg.VRFSecret,
		minEpochInterval:   cfg.MinEpochInterval,
		maxEpochInterval:   cfg.MaxEpochInterval,
		retryEpochInterval: cfg.RetryEpochInterval,
		db:                 db,
		log:                log,
		stop:               make(chan struct{}),
		wr:                 NewWaitingRoom(),

		// TODO: change when using actual replication
		leaderHint:    true,
		leaderHintSet: nil,

		clk:          clk,
		canEpochSet:  clk.Timer(0),
		mustEpochSet: clk.Timer(0),
		retryEpoch:   clk.Timer(0),
	}

	switch replicaStateBytes, err := db.Get(tableReplicaState); err {
	case ks.db.ErrNotFound():
		// ReplicaState zero value is valid initialization
	case nil:
		if err := ks.rs.Unmarshal(replicaStateBytes); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	ks.resetEpochTimers(ks.rs.LastEpochDelimiter.Timestamp.Time())

	ks.vmb = NewVerifierBroadcast(ks.rs.NextIndexVerifier)

	ok := false
	if cfg.UpdateAddr != "" {
		ks.updateServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.UpdateTLS)))
		proto.RegisterE2EKSUpdateServer(ks.updateServer, ks)
		ks.updateListen, err = net.Listen("tcp", cfg.UpdateAddr)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				ks.updateListen.Close()
			}
		}()
	}
	if cfg.LookupAddr != "" {
		ks.lookupServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.LookupTLS)))
		proto.RegisterE2EKSLookupServer(ks.lookupServer, ks)
		ks.lookupListen, err = net.Listen("tcp", cfg.LookupAddr)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				ks.lookupListen.Close()
			}
		}()
	}
	if cfg.VerifierAddr != "" {
		ks.verifierServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.VerifierTLS)))
		proto.RegisterE2EKSVerificationServer(ks.verifierServer, ks)
		ks.verifierListen, err = net.Listen("tcp", cfg.VerifierAddr)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				ks.verifierListen.Close()
			}
		}()
	}
	ks.merkletree, err = merkletree.AccessMerkleTree(ks.db, []byte{tableMerkleTreePrefix}, cfg.TreeNonce)
	if err != nil {
		return nil, err
	}
	var currentSnapshot uint64
	switch currentSnapshotBytes, err := db.Get(tableMerkleTreeCurrentSnapshot); err {
	case ks.db.ErrNotFound():
		// empty snapshot
		currentSnapshot = 0
	case nil:
		currentSnapshot = binary.BigEndian.Uint64(currentSnapshotBytes)
	default:
		return nil, err
	}
	ks.latestTree, err = ks.merkletree.GetSnapshot(currentSnapshot).BeginModification()
	if err != nil {
		return nil, err
	}

	ok = true
	return ks, nil
}

// Start makes the keyserver start handling requests (forks goroutines).
func (ks *Keyserver) Start() {
	ks.log.Start(ks.rs.NextIndexLog)
	if ks.updateServer != nil {
		go ks.updateServer.Serve(ks.updateListen)
	}
	if ks.lookupServer != nil {
		go ks.lookupServer.Serve(ks.lookupListen)
	}
	if ks.verifierServer != nil {
		go ks.verifierServer.Serve(ks.verifierListen)
	}
	ks.waitStop.Add(1)
	go func() { ks.run(); ks.waitStop.Done() }()
}

// Stop cleanly shuts down the keyserver and then returns.
// TODO: figure out what will happen to connected clients?
func (ks *Keyserver) Stop() {
	ks.stopOnce.Do(func() {
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
	})
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
			// TODO: allow multiple steps per log entry (pipelining). Maybe
			// this would be better implemented at the log level?
			ks.step(&step, &ks.rs, wb)
			ks.rs.NextIndexLog++
			wb.Put(tableReplicaState, proto.MustMarshal(&ks.rs))
			if err := ks.db.Write(wb); err != nil {
				log.Panicf("sync step to db: %s", err)
			}
			wb.Reset()
			step.Reset()
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
		runtime.Gosched()
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (ks *Keyserver) step(step *proto.KeyserverStep, rs *proto.ReplicaState, wb kv.Batch) {
	// ks: &const
	// step, rs, wb: &mut
	switch {
	case step.Update != nil:
		index := step.Update.Update.NewEntry.Index
		prevUpdate, err := ks.getUpdate(index, ks.rs.LastEpochDelimiter.EpochNumber)
		if err != nil {
			// TODO: return the client-bound error code
			return
		}
		if err := common.VerifyUpdate(&prevUpdate.Update.NewEntry.Entry, step.Update.Update); err != nil {
			// TODO: return the client-bound error code
			return
		}
		entryHash := sha256.Sum256(step.Update.Update.NewEntry.PreservedEncoding)
		if err := ks.latestTree.Set(index, entryHash[:]); err != nil {
			// TODO: return the client-bound error code
			return
		}
		ks.latestTree, err = ks.latestTree.Flush(wb).BeginModification()
		if err != nil {
			// TODO: return the client-bound error code
			return
		}
		rs.PendingUpdates = true
		wb.Put(tableUpdateRequests(step.Update.Update.NewEntry.Index, ks.rs.LastEpochDelimiter.EpochNumber+1), proto.MustMarshal(step.Update))
		ks.verifierLogAppend(&proto.VerifierStep{Update: step.Update.Update}, rs, wb)

	case step.EpochDelimiter != nil:
		if step.EpochDelimiter.EpochNumber <= rs.LastEpochDelimiter.EpochNumber {
			return // a duplicate of this step has already been handled
		}
		rs.LastEpochDelimiter = *step.EpochDelimiter
		rs.PendingUpdates = false
		ks.resetEpochTimers(rs.LastEpochDelimiter.Timestamp.Time())

		seh := &proto.SignedEpochHead{
			Head: proto.TimestampedEpochHead_PreserveEncoding{proto.TimestampedEpochHead{
				Head: proto.EpochHead_PreserveEncoding{proto.EpochHead{
					RootHash:            nil, // TODO(dmz): ret.TreeProof = merklemap.GetRootHash()
					PreviousSummaryHash: rs.PreviousSummaryHash,
					Realm:               ks.realm,
					Epoch:               step.EpochDelimiter.EpochNumber,
				}, nil},
				Timestamp: step.EpochDelimiter.Timestamp,
			}, nil},
			Signatures: make(map[uint64][]byte, 1),
		}

		seh.Head.Head.UpdateEncoding()
		h := sha256.Sum256(seh.Head.Head.PreservedEncoding)
		rs.PreviousSummaryHash = h[:]

		seh.Head.UpdateEncoding()
		seh.Signatures[ks.replicaID] = ed25519.Sign(ks.sehKey, proto.MustMarshal(&seh.Head))[:]
		ks.log.Propose(context.TODO(), proto.MustMarshal(&proto.KeyserverStep{ReplicaSigned: seh}))
		// TODO: Propose may fail silently when replicas crash. We want to
		// keep retrying ReplicaRatifications because if not enough of
		// them go in, the epoch will not be properly signed. Note that it
		// is okay to create new epochs while we dont have signatures for the
		// last one, but we must eventually sign all of them, otherwise
		// verifiers will block indefinitely. It may or may not be worth
		// unifying this with epoch delimiter retry logic -- we need one epoch
		// delimiter per cluster but a majority of replicas need to sign.

	case step.ReplicaSigned != nil:
		rNew := step.ReplicaSigned
		dbkey := tableRatifications(rNew.Head.Head.Epoch, ks.serverID)
		switch rExistingBytes, err := ks.db.Get(dbkey); err {
		default: // not nil and not ignored
			log.Panicf("db.Get(tableRatifications(%d, %d)) failed: %s", rNew.Head.Head.Epoch, ks.serverID, err)
		case ks.db.ErrNotFound():
			wb.Put(dbkey, proto.MustMarshal(rNew))
		case nil:
			rExisting := new(proto.SignedEpochHead)
			if err := rExisting.Unmarshal(rExistingBytes); err != nil {
				log.Panicf("tableRatifications(%d, %d) invalid (this is our ID!): %s", rNew.Head.Head.Epoch, ks.serverID, err)
			}
			if !rExisting.Head.Equal(rNew.Head) {
				log.Panicf("tableRatifications(%d, %d) differs from another replica: %s (%#v != %#v)", rNew.Head.Head.Epoch, ks.serverID, rExisting.Head.VerboseEqual(rNew.Head), rExisting.Head, rNew.Head)
			}
			for id, sig := range rNew.Signatures {
				if _, already := rExisting.Signatures[id]; !already {
					rExisting.Signatures[id] = sig
				}
			}
			wb.Put(dbkey, proto.MustMarshal(rExisting))
			rNew = rExisting
		}
		// TODO: check against the cluster configuration that the signatures we
		// have are sufficient to pass verification. For now, 1 is a majority of 1.
		// Only put signatures into the verifier log once.
		if true {
			// FIXME: make sure sehs in verifier log are ordered by epoch
			ks.verifierLogAppend(&proto.VerifierStep{Epoch: rNew}, rs, wb)
		}
	case step.VerifierSigned != nil:
		rNew := step.VerifierSigned
		for id := range rNew.Signatures {
			if id == ks.serverID {
				log.Printf("verifier sent us an acclaimed signature with our id :/")
				continue
			}
			dbkey := tableRatifications(rNew.Head.Head.Epoch, id)
			wb.Put(dbkey, proto.MustMarshal(rNew))
			ks.wr.Notify(step.UID, nil)
		}
	default:
		log.Panicf("unknown step pb in replicated log: %#v", step)
	}
	return
}

// shouldEpoch returns true if this node should append an epoch delimiter to the
// log. see replication.proto for details.
func (ks *Keyserver) shouldEpoch() bool {
	return ks.leaderHint && (ks.mustEpoch || ks.canEpoch && ks.rs.PendingUpdates)
}

// maybeEpoch proposes an epoch delimiter for inclusion in the log if necessary.
func (ks *Keyserver) maybeEpoch() {
	if !ks.shouldEpoch() {
		return
	}
	ks.log.Propose(context.TODO(), proto.MustMarshal(&proto.KeyserverStep{EpochDelimiter: &proto.EpochDelimiter{
		EpochNumber: ks.rs.LastEpochDelimiter.EpochNumber + 1,
		Timestamp:   proto.Time(ks.clk.Now()),
	}}))
	ks.canEpochSet.Stop()
	ks.mustEpochSet.Stop()
	ks.retryEpoch.Reset(ks.retryEpochInterval)
}

func (ks *Keyserver) resetEpochTimers(t time.Time) {
	t2 := t.Add(ks.minEpochInterval)
	d := t2.Sub(ks.clk.Now())
	ks.canEpochSet.Reset(d)
	ks.mustEpochSet.Reset(d)
	ks.retryEpoch.Stop()
	ks.canEpoch = false
	ks.mustEpoch = false
}

func genUID() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Panicf("rand.Read: %s", err)
	}
	return binary.BigEndian.Uint64(buf[:])
}
