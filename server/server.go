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
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/yahoo/coname"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/merkletree"
	"github.com/yahoo/coname/server/replication"
	"github.com/yahoo/coname/server/replication/kvlog"
	"github.com/yahoo/coname/vrf"

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

	MinEpochInterval, MaxEpochInterval, RetryProposalInterval time.Duration
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

	clk clock.Clock

	minEpochInterval, maxEpochInterval, retryProposalInterval time.Duration

	// epochProposer makes sure we try to advance epochs.
	epochProposer *Proposer
	// whether we should be advancing epochs is determined based on the
	// following variables (sensitivity list wantEpochProposer) {
	leaderHint    bool
	leaderHintSet <-chan bool

	minEpochIntervalPassed, maxEpochIntervalPassed bool
	minEpochIntervalTimer, maxEpochIntervalTimer   *clock.Timer
	// rs.PendingUpdates
	// rs.ThisReplicaNeedsToSignLastEpoch
	// }

	// signatureProposer makes sure we try to sign epochs.
	signatureProposer *Proposer
	// whether our signature is needed is determined by this sensitivity list {
	// rs.ThisReplicaNeedsToSignLastEpoch
	//}

	vmb *VerifierBroadcast
	wr  *WaitingRoom

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}

	merkletree *merkletree.MerkleTree

	epochPending, signaturePending []uint64
}

// Open initializes a new keyserver based on cfg, reads the persistent state and
// binds to the specified ports. It does not handle input: requests will block.
func Open(cfg *Config, db kv.DB, clk clock.Clock) (ks *Keyserver, err error) {
	log, err := kvlog.New(db, []byte{tableReplicationLogPrefix})
	if err != nil {
		return nil, err
	}

	ks = &Keyserver{
		realm:                 cfg.Realm,
		serverID:              cfg.ServerID,
		replicaID:             cfg.ReplicaID,
		sehKey:                cfg.RatificationKey,
		vrfSecret:             cfg.VRFSecret,
		minEpochInterval:      cfg.MinEpochInterval,
		maxEpochInterval:      cfg.MaxEpochInterval,
		retryProposalInterval: cfg.RetryProposalInterval,
		db:      db,
		log:     log,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
		wr:      NewWaitingRoom(),

		// TODO: change when using actual replication
		leaderHintSet: nil,

		clk: clk,
		minEpochIntervalTimer: clk.Timer(0),
		maxEpochIntervalTimer: clk.Timer(0),

		epochPending:     make([]uint64, 0),
		signaturePending: make([]uint64, 0),
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
	ks.leaderHint = true
	ks.resetEpochTimers(ks.rs.LastEpochDelimiter.Timestamp.Time())
	ks.updateEpochProposer()

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
	go ks.run()
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
		<-ks.stopped
		ks.minEpochIntervalTimer.Stop()
		ks.maxEpochIntervalTimer.Stop()
		ks.epochProposer.Stop()
		ks.signatureProposer.Stop()
		ks.log.Stop()
	})
}

// run is the CSP-style main loop of the keyserver. All code critical for safe
// persistence should be directly in run. All functions called from run should
// either interpret data and modify their mutable arguments OR interact with the
// network and disk, but not both.
func (ks *Keyserver) run() {
	defer close(ks.stopped)
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
			deferredIO := ks.step(&step, &ks.rs, wb)
			ks.rs.NextIndexLog++
			wb.Put(tableReplicaState, proto.MustMarshal(&ks.rs))
			if err := ks.db.Write(wb); err != nil {
				log.Panicf("sync step to db: %s", err)
			}
			wb.Reset()
			step.Reset()
			if deferredIO != nil {
				deferredIO()
			}
		case ks.leaderHint = <-ks.leaderHintSet:
			ks.updateEpochProposer()
		case <-ks.minEpochIntervalTimer.C:
			ks.minEpochIntervalPassed = true
			ks.updateEpochProposer()
		case <-ks.maxEpochIntervalTimer.C:
			ks.maxEpochIntervalPassed = true
			ks.updateEpochProposer()
		}
		runtime.Gosched()
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (ks *Keyserver) step(step *proto.KeyserverStep, rs *proto.ReplicaState, wb kv.Batch) (deferredIO func()) {
	// ks: &const
	// step, rs, wb: &mut
	switch {
	case step.Update != nil:
		index := step.Update.Update.NewEntry.Index
		prevUpdate, err := ks.getUpdate(index, rs.LastEpochDelimiter.EpochNumber)
		if err != nil {
			ks.wr.Notify(step.UID, fmt.Errorf("internal error"))
			return
		}
		var prevEntry *proto.Entry
		if prevUpdate != nil {
			prevEntry = &prevUpdate.Update.NewEntry.Entry
		}
		if err := coname.VerifyUpdate(prevEntry, step.Update.Update); err != nil {
			ks.wr.Notify(step.UID, err)
			return
		}
		entryHash := sha256.Sum256(step.Update.Update.NewEntry.PreservedEncoding)
		latestTree := ks.merkletree.GetSnapshot(rs.LatestTreeSnapshot)
		newTree, err := latestTree.BeginModification()
		if err != nil {
			ks.wr.Notify(step.UID, fmt.Errorf("internal error"))
			return
		}
		if err := newTree.Set(index, entryHash[:]); err != nil {
			ks.wr.Notify(step.UID, fmt.Errorf("internal error"))
			return
		}
		rs.LatestTreeSnapshot = newTree.Flush(wb).Nr
		epochNr := rs.LastEpochDelimiter.EpochNumber + 1
		wb.Put(tableUpdateRequests(index, epochNr), proto.MustMarshal(step.Update))
		ks.epochPending = append(ks.epochPending, step.UID)
		println("U", step.UID)

		rs.PendingUpdates = true
		ks.updateEpochProposer()

		return ks.verifierLogAppend(&proto.VerifierStep{Update: step.Update.Update}, rs, wb)

	case step.EpochDelimiter != nil:
		if step.EpochDelimiter.EpochNumber <= rs.LastEpochDelimiter.EpochNumber {
			return // a duplicate of this step has already been handled
		}
		rs.LastEpochDelimiter = *step.EpochDelimiter

		rs.PendingUpdates = false
		ks.resetEpochTimers(rs.LastEpochDelimiter.Timestamp.Time())
		rs.ThisReplicaNeedsToSignLastEpoch = true
		ks.updateEpochProposer()
		ks.signaturePending, ks.epochPending = ks.epochPending, nil
		deferredIO = ks.updateSignatureProposer

		snapshotNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(snapshotNumberBytes, rs.LatestTreeSnapshot)
		wb.Put(tableMerkleTreeSnapshot(step.EpochDelimiter.EpochNumber), snapshotNumberBytes)

		latestTree := ks.merkletree.GetSnapshot(rs.LatestTreeSnapshot)
		rootHash, err := latestTree.GetRootHash()
		if err != nil {
			log.Panicf("ks.latestTree.GetRootHash() failed: %s", err)
		}
		seh := &proto.SignedEpochHead{
			Head: proto.TimestampedEpochHead_PreserveEncoding{proto.TimestampedEpochHead{
				Head: proto.EpochHead_PreserveEncoding{proto.EpochHead{
					RootHash:            rootHash,
					PreviousSummaryHash: rs.PreviousSummaryHash,
					Realm:               ks.realm,
					Epoch:               step.EpochDelimiter.EpochNumber,
				}, nil},
				Timestamp: step.EpochDelimiter.Timestamp,
			}, nil},
			Signatures: make(map[uint64][]byte),
		}
		seh.Head.Head.UpdateEncoding()
		h := sha256.Sum256(seh.Head.Head.PreservedEncoding)
		rs.PreviousSummaryHash = h[:]
		seh.Head.UpdateEncoding()

		wb.Put(tableRatifications(step.EpochDelimiter.EpochNumber, ks.serverID), proto.MustMarshal(seh))

		println("D", rs.LastEpochDelimiter.EpochNumber)

	case step.ReplicaSigned != nil:
		newSEH := step.ReplicaSigned
		dbkey := tableRatifications(newSEH.Head.Head.Epoch, ks.serverID)
		sehBytes, err := ks.db.Get(dbkey)
		if err != nil {
			log.Panicf("db.Get(tableRatifications(%d, %d)) failed: %s", newSEH.Head.Head.Epoch, ks.serverID, err)
		}
		seh := new(proto.SignedEpochHead)
		if err := seh.Unmarshal(sehBytes); err != nil {
			log.Panicf("tableRatifications(%d, %d) invalid (this is our ID!): %s",
				newSEH.Head.Head.Epoch, ks.serverID, err)
		}
		if !seh.Head.Equal(newSEH.Head) {
			log.Panicf("tableRatifications(%d, %d) differs from another replica: %s (%#v != %#v)",
				newSEH.Head.Head.Epoch, ks.serverID, seh.Head.VerboseEqual(newSEH.Head), seh.Head, newSEH.Head)
		}
		println("R", newSEH.Head.Head.Epoch)

		if seh.Signatures == nil {
			seh.Signatures = make(map[uint64][]byte, 1)
		}
		for id, sig := range newSEH.Signatures {
			if _, already := seh.Signatures[id]; !already {
				seh.Signatures[id] = sig
			}
		}
		log.Print(seh)
		wb.Put(dbkey, proto.MustMarshal(seh))

		if rs.ThisReplicaNeedsToSignLastEpoch && newSEH.Signatures[ks.replicaID] != nil {
			rs.ThisReplicaNeedsToSignLastEpoch = false
			ks.updateEpochProposer()
			// updateSignatureProposer should in general be called after writes
			// have been flused to db, but given ThisReplicaNeedsToSignLast =
			// false we know that updateSignatureProposer will not access the db.
			ks.updateSignatureProposer()
		}
		// TODO: check against the cluster configuration that the signatures we
		// have are sufficient to pass verification. For now, 1 is a majority of 1.
		// Only put signatures into the verifier log once.
		if true {
			notifyVerifiers := ks.verifierLogAppend(&proto.VerifierStep{Epoch: seh}, rs, wb)
			return func() {
				notifyVerifiers()
				for _, uid := range ks.signaturePending {
					println("done", uid)
					ks.wr.Notify(uid, nil)
				}
				ks.signaturePending = nil
			}
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
		}
		ks.wr.Notify(step.UID, nil)
	default:
		log.Panicf("unknown step pb in replicated log: %#v", step)
	}
	return
}

type Proposer struct {
	log      replication.LogReplicator
	clk      clock.Clock
	delay    time.Duration
	proposal []byte

	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

func StartProposer(log replication.LogReplicator, clk clock.Clock, initialDelay time.Duration, proposal []byte) *Proposer {
	p := &Proposer{
		log:      log,
		clk:      clk,
		delay:    initialDelay,
		proposal: proposal,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	println("start", p)
	go p.run()
	return p
}

func (p *Proposer) Stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stop)
		<-p.stopped
	})
}

func (p *Proposer) run() {
	defer close(p.stopped)
	timer := p.clk.Timer(0)
	for {
		println("loop", p)
		select {
		case <-timer.C:
			println("propose", p)
			p.log.Propose(context.TODO(), p.proposal)
			println("proposed", p)
			timer.Reset(p.delay)
			p.delay = p.delay * 2
		case <-p.stop:
			println("stop", p)
			return
		}
	}
}

// shouldEpoch returns true if this node should append an epoch delimiter to the
// log.
func (ks *Keyserver) wantEpochProposer() bool {
	if ks.rs.ThisReplicaNeedsToSignLastEpoch {
		return false
	}
	return ks.leaderHint && (ks.maxEpochIntervalPassed || ks.minEpochIntervalPassed && ks.rs.PendingUpdates)
}

// maybeEpoch either starts or stops the epoch delimiter proposer as necessary
func (ks *Keyserver) updateEpochProposer() {
	want := ks.wantEpochProposer()
	have := ks.epochProposer != nil
	if have == want {
		return
	}

	switch want {
	case true:
		ks.epochProposer = StartProposer(ks.log, ks.clk, ks.retryProposalInterval,
			proto.MustMarshal(&proto.KeyserverStep{EpochDelimiter: &proto.EpochDelimiter{
				EpochNumber: ks.rs.LastEpochDelimiter.EpochNumber + 1,
				Timestamp:   proto.Time(ks.clk.Now()),
			}}))
	case false:
		ks.epochProposer.Stop()
		ks.epochProposer = nil
	}
}

func (ks *Keyserver) updateSignatureProposer() {
	// invariant: do not access the db if ThisReplicaNeedsToSignLastEpoch = false
	want := ks.rs.ThisReplicaNeedsToSignLastEpoch
	have := ks.signatureProposer != nil
	println(have, want)
	if have == want {
		return
	}

	switch want {
	case true:
		sehBytes, err := ks.db.Get(tableRatifications(ks.rs.LastEpochDelimiter.EpochNumber, ks.serverID))
		if err != nil {
			log.Panicf("ThisReplicaSignedLastEpoch but no SEH for last epoch in db", err)
		}
		seh := new(proto.SignedEpochHead)
		if err := seh.Unmarshal(sehBytes); err != nil {
			log.Panicf("tableRatifications(%d, %d) invalid (this is our ID!): %s", ks.rs.LastEpochDelimiter.EpochNumber, ks.serverID, err)
		}
		seh.Signatures = map[uint64][]byte{ks.replicaID: ed25519.Sign(ks.sehKey, seh.Head.PreservedEncoding)[:]}
		ks.signatureProposer = StartProposer(ks.log, ks.clk, ks.retryProposalInterval,
			proto.MustMarshal(&proto.KeyserverStep{ReplicaSigned: seh}))
	case false:
		ks.signatureProposer.Stop()
		ks.signatureProposer = nil
	}
}

func (ks *Keyserver) resetEpochTimers(t time.Time) {
	t2 := t.Add(ks.minEpochInterval)
	d := t2.Sub(ks.clk.Now())
	ks.minEpochIntervalTimer.Reset(d)
	ks.maxEpochIntervalTimer.Reset(d)
	ks.minEpochIntervalPassed = false
	ks.maxEpochIntervalPassed = false
	// caller MUST call updateEpochProposer
}

func genUID() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Panicf("rand.Read: %s", err)
	}
	return binary.BigEndian.Uint64(buf[:])
}
