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
	"crypto"
	"encoding/binary"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/yahoo/coname"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/merkletree"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Verifier verifies that the Keyserver of the realm is not cheating.
// The veirifier is not replicated because one can just run several.
type Verifier struct {
	realm         string
	keyserverAddr string
	auth          credentials.TransportAuthenticator

	id         uint64
	signingKey *[ed25519.PrivateKeySize]byte

	db kv.DB
	vs proto.VerifierState

	keyserver proto.E2EKSVerificationClient

	stop     context.CancelFunc
	ctx      context.Context
	waitStop sync.WaitGroup

	merkletree *merkletree.MerkleTree
	latestTree *merkletree.Snapshot
}

// Start initializes a new verifier based on config and db, or returns an error
// if initialization fails. It then starts the worker goroutine(s).
func Start(cfg *proto.VerifierConfig, db kv.DB, getKey func(string) (crypto.PrivateKey, error)) (*Verifier, error) {
	tls, err := cfg.TLS.Config(getKey)
	if err != nil {
		return nil, err
	}
	sk, err := getKey(cfg.SigningKeyID)
	if err != nil {
		return nil, err
	}

	vr := &Verifier{
		id:    cfg.ID,
		realm: cfg.Realm,

		signingKey:    sk.(*[ed25519.PrivateKeySize]byte),
		keyserverAddr: cfg.KeyserverAddr,
		auth:          credentials.NewTLS(tls),

		db: db,
	}
	vr.ctx, vr.stop = context.WithCancel(context.Background())

	switch verifierStateBytes, err := db.Get(tableVerifierState); err {
	case vr.db.ErrNotFound():
		vr.vs.KeyserverAuth = &cfg.InitialKeyserverAuth
		vr.vs.NextEpoch = 1
	case nil:
		if err := vr.vs.Unmarshal(verifierStateBytes); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	vr.merkletree, err = merkletree.AccessMerkleTree(vr.db, []byte{tableMerkleTreePrefix}, cfg.TreeNonce)
	if err != nil {
		return nil, err
	}

	vr.waitStop.Add(1)
	go func() { vr.run(); vr.waitStop.Done() }()
	return vr, nil
}

// Stop cleanly shuts down the verifier and then returns.
func (vr *Verifier) Stop() {
	vr.stop()
	vr.waitStop.Wait()
}

func (vr *Verifier) shuttingDown() bool {
	select {
	case <-vr.ctx.Done():
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
	keyserverConnection, err := grpc.Dial(vr.keyserverAddr, grpc.WithTransportCredentials(vr.auth))
	if err != nil {
		log.Panicf("dial %s: %s", vr.keyserverAddr, err)
	}
	vr.keyserver = proto.NewE2EKSVerificationClient(keyserverConnection)
	stream, err := vr.keyserver.VerifierStream(vr.ctx, &proto.VerifierStreamRequest{
		Start:    vr.vs.NextIndex,
		PageSize: math.MaxUint64,
	})
	if err != nil {
		keyserverConnection.Close()
		log.Panicf("VerifierStream: %s", err)
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
		wb.Put(tableVerifierState, proto.MustMarshal(&vr.vs))
		if err := vr.db.Write(wb); err != nil {
			log.Panicf("sync step to db: %s", err)
		}
		wb.Reset()
		if deferredIO != nil {
			deferredIO()
		}
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (vr *Verifier) step(step *proto.VerifierStep, vs *proto.VerifierState, wb kv.Batch) (deferredIO func()) {
	// vr: &const
	// step, vs, wb: &mut
	switch step.Type.(type) {
	case *proto.VerifierStep_Update:
		index := step.GetUpdate().NewEntry.Index
		prevEntry, err := vr.getEntry(index, vs.NextEpoch)
		if err := coname.VerifyUpdate(prevEntry, step.GetUpdate()); err != nil {
			// the keyserver should filter all bad updates
			log.Panicf("%d: bad update %v: %s", vs.NextIndex, *step, err)
		}
		var entryHash [32]byte
		sha3.ShakeSum256(entryHash[:], step.GetUpdate().NewEntry.Encoding)
		latestTree := vr.merkletree.GetSnapshot(vs.LatestTreeSnapshot)
		newTree, err := latestTree.BeginModification()
		if err != nil {
			log.Panicf("%d: BeginModification(): %s", vs.NextIndex, err)
		}
		if err := newTree.Set(index, entryHash[:]); err != nil {
			log.Panicf("%d: Set(%x,%x): %s", vs.NextIndex, index, entryHash[:], err)
		}
		vs.LatestTreeSnapshot = newTree.Flush(wb).Nr
		wb.Put(tableEntries(index, vs.NextEpoch), step.GetUpdate().NewEntry.Encoding)

	case *proto.VerifierStep_Epoch:
		ok := coname.VerifyPolicy(vr.vs.KeyserverAuth, step.GetEpoch().Head.Encoding, step.GetEpoch().Signatures)
		// the bad steps here will not get persisted to disk right now. do we want them to?
		if !ok {
			log.Panicf("%d: keyserver signature verification failed: %#v", vs.NextIndex, *step)
		}
		r := step.GetEpoch().Head
		if r.Head.Realm != vr.realm {
			log.Panicf("%d: seh for realm %q, expected %q: %#v", vs.NextEpoch, r.Head.Realm, vr.realm, *step)
		}
		if r.Head.Epoch != vs.NextEpoch {
			log.Panicf("%d: got epoch %d instead: %#v", vs.NextEpoch, r.Head.Epoch, *step)
		}
		s := r.Head
		if !bytes.Equal(s.PreviousSummaryHash, vs.PreviousSummaryHash) {
			log.Panicf("%d: seh with previous summary hash %q, expected %q: %#v", vs.NextEpoch, s.PreviousSummaryHash, vs.PreviousSummaryHash, *step)
		}
		latestTree := vr.merkletree.GetSnapshot(vs.LatestTreeSnapshot)
		rootHash, err := latestTree.GetRootHash()
		if err != nil {
			log.Panicf("GetRootHash() failed: %s", err)
		}
		if !bytes.Equal(s.RootHash, rootHash) {
			log.Panicf("%d: seh with root hash %q, expected %q: %#v", vs.NextEpoch, s.RootHash, rootHash, *step)
		}
		seh := &proto.SignedEpochHead{
			Head: proto.EncodedTimestampedEpochHead{proto.TimestampedEpochHead{
				Head:      s,
				Timestamp: proto.Time(time.Now()),
			}, nil},
			Signatures: make(map[uint64][]byte, 1),
		}
		if vs.PreviousSummaryHash == nil {
			vs.PreviousSummaryHash = make([]byte, 64)
		}
		sha3.ShakeSum256(vs.PreviousSummaryHash[:], seh.Head.Head.Encoding)
		seh.Head.UpdateEncoding()
		seh.Signatures[vr.id] = ed25519.Sign(vr.signingKey, proto.MustMarshal(&seh.Head))[:]
		wb.Put(tableRatifications(vs.NextEpoch, vr.id), proto.MustMarshal(seh))
		vs.NextEpoch++
		return func() {
			_, err := vr.keyserver.PushRatification(vr.ctx, seh)
			if err != nil {
				log.Printf("PushRatification: %s", err)
			}
		}
	default:
		log.Panicf("%d: unknown step: %#v", vs.NextIndex, *step)
	}
	return
}

// getEntry returns the last version of the entry at idx during or before epoch.
// If there is no such update, (nil, nil) is returned.
func (vr *Verifier) getEntry(idx []byte, epoch uint64) (*proto.Entry, error) {
	// idx: []&const
	prefixIdxEpoch := make([]byte, 1+vrf.Size+8)
	prefixIdxEpoch[0] = tableEntriesPrefix
	copy(prefixIdxEpoch[1:], idx)
	if epoch == math.MaxUint64 {
		log.Panicf("epoch number too big, would overflow")
	}
	binary.BigEndian.PutUint64(prefixIdxEpoch[1+len(idx):], epoch+1)
	iter := vr.db.NewIterator(&kv.Range{
		Start: prefixIdxEpoch[:1+len(idx)],
		Limit: prefixIdxEpoch,
	})
	if !iter.Last() {
		if iter.Error() != nil {
			return nil, iter.Error()
		}
		return nil, nil
	}
	ret := new(proto.Entry)
	if err := ret.Unmarshal(iter.Value()); err != nil {
		return nil, iter.Error()
	}
	iter.Release()
	return ret, nil
}
