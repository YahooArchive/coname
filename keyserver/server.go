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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/yahoo/coname"
	"github.com/yahoo/coname/concurrent"
	"github.com/yahoo/coname/hkpfront"
	"github.com/yahoo/coname/httpfront"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/merkletree"
	"github.com/yahoo/coname/keyserver/oidc"
	"github.com/yahoo/coname/keyserver/replication"
	"github.com/yahoo/coname/keyserver/saml"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Keyserver manages a single end-to-end keyserver realm.
type Keyserver struct {
	realm               string
	serverID, replicaID uint64
	serverAuthorized    *proto.AuthorizationPolicy

	sehKey    *[ed25519.PrivateKeySize]byte
	vrfSecret *[vrf.SecretKeySize]byte

	dkimProofToAddr         string
	dkimProofSubjectPrefix  string
	dkimProofAllowedDomains map[string]struct{}
	oidcProofConfig         []OIDCConfig

	samlProofAllowedDomains     map[string]struct{}
	samlProofIDPSSOURL          string
	samlProofConsumerServiceURL string
	samlProofIDPCert            *x509.Certificate
	samlProofSPKey              crypto.PrivateKey
	samlProofValidity           time.Duration

	insecureSkipEmailProof bool

	db  kv.DB	// local or shared
	log replication.LogReplicator
	rs  proto.ReplicaState

	publicServer, verifierServer                             *grpc.Server
	hkpFront                                                 *hkpfront.HKPFront
	httpFront                                                *httpfront.HTTPFront
	publicListen, verifierListen, hkpListen, httpFrontListen net.Listener

	clk       clock.Clock
	lookupTXT func(string) ([]string, error)

	clientTimeout       time.Duration
	laggingVerifierScan uint64

	minEpochInterval, maxEpochInterval, retryProposalInterval time.Duration

	// epochProposer makes sure we try to advance epochs.
	epochProposer *Proposer
	// whether we should be advancing epochs is determined based on the
	// following variables (sensitivity list wantEpochProposer) {
	leaderHint bool

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

	merkletree *merkletree.MerkleTree

	sb                 *concurrent.SequenceBroadcast
	wr                 *concurrent.OneShotPubSub
	signatureBroadcast *concurrent.PublishSubscribe

	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}

	inRotation   bool
	inRotationMu sync.Mutex
}

type KeyserverParameters struct {
	DB kv.DB	// DB, local or shared
	Log replication.LogReplicator	// replica
	Clk clock.Clock
	WR *concurrent.OneShotPubSub
	PS *concurrent.PublishSubscribe
	Merkletree *merkletree.MerkleTree
	GetKey func(string) (crypto.PrivateKey, error)
	LookupTXT func(string) ([]string, error)
	Policy *proto.AuthorizationPolicy
}

// OIDCConfig manages an OpenID Connect object
type OIDCConfig struct {
	allowedDomains map[string]struct{}
	oidcClient     *oidc.Client
	scope          string
}

type errExpired struct {
	err error
}

func (e *errExpired) Error() string {
	return e.err.Error()
}

func isExpired(err error) bool {
	_, ok := err.(*errExpired)
	return ok
}

func majority(nReplicas int) int {
	return nReplicas/2 + 1
}

func ratificationPolicy(cfg *proto.ReplicaConfig) *proto.AuthorizationPolicy {
	// TODO: since we only want to support precisely this ratification policy,
	// this should be moved into server.go
	ratificationPolicy := &proto.AuthorizationPolicy{
		PublicKeys: make(map[uint64]*proto.PublicKey),
		PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
			Threshold: uint32(majority(len(cfg.KeyserverConfig.InitialReplicas)))},
		},
	}
	for _, replica := range cfg.KeyserverConfig.InitialReplicas {
		replicaExpr := &proto.QuorumExpr{
			Threshold: 1,
		}
		for _, pk := range replica.PublicKeys {
			pkid := proto.KeyID(pk)
			ratificationPolicy.PublicKeys[pkid] = pk
			replicaExpr.Candidates = append(replicaExpr.Candidates, pkid)
		}
		ratificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum).Quorum.Subexpressions = append(ratificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum).Quorum.Subexpressions, replicaExpr)
	}
	return ratificationPolicy
}

// Open initializes a new keyserver based on cfg, reads the persistent state and
// binds to the specified ports. It does not handle input: requests will block.
func Open(cfg *proto.ReplicaConfig, kp *KeyserverParameters) (*Keyserver, error) {
	signingKey, err := kp.GetKey(cfg.SigningKeyID)
	if err != nil {
		return nil, err
	}
	vrfKey, err := kp.GetKey(cfg.VRFKeyID)
	if err != nil {
		return nil, err
	}
	publicTLS, err := cfg.PublicTLS.Config(kp.GetKey)
	if err != nil {
		return nil, err
	}
	verifierTLS, err := cfg.VerifierTLS.Config(kp.GetKey)
	if err != nil {
		return nil, err
	}
	hkpTLS, err := cfg.HKPTLS.Config(kp.GetKey)
	if err != nil {
		return nil, err
	}

	httpFrontTLS, err := cfg.HTTPFrontTLS.Config(kp.GetKey)
	if err != nil {
		return nil, err
	}

	policy := kp.Policy
	if policy == nil {
		policy = ratificationPolicy(cfg)
	}

	ks := &Keyserver{
		realm:                   cfg.Realm,
		serverID:                cfg.ServerID,
		replicaID:               cfg.ReplicaID,
		serverAuthorized:        policy,
		sehKey:                  signingKey.(*[ed25519.PrivateKeySize]byte),
		vrfSecret:               vrfKey.(*[vrf.SecretKeySize]byte),
		laggingVerifierScan:     cfg.LaggingVerifierScan,
		clientTimeout:           cfg.ClientTimeout.Duration(),
		minEpochInterval:        cfg.MinEpochInterval.Duration(),
		maxEpochInterval:        cfg.MaxEpochInterval.Duration(),
		retryProposalInterval:   cfg.ProposalRetryInterval.Duration(),
		dkimProofAllowedDomains: make(map[string]struct{}),
		oidcProofConfig:         make([]OIDCConfig, 0),
		samlProofAllowedDomains: make(map[string]struct{}),

		db:                 kp.DB,
		log:                kp.Log,
		stop:               make(chan struct{}),
		stopped:            make(chan struct{}),
		wr:                 kp.WR,
		signatureBroadcast: kp.PS,

		merkletree:         kp.Merkletree,

		leaderHint: true,
		inRotation: true,

		clk:                   kp.Clk,
		lookupTXT:             kp.LookupTXT,
		minEpochIntervalTimer: kp.Clk.Timer(0),
		maxEpochIntervalTimer: kp.Clk.Timer(0),
	}

	for _, p := range cfg.RegistrationPolicy {
		switch t := p.PolicyType.(type) {
		case *proto.RegistrationPolicy_EmailProofByDKIM:
			for _, d := range t.EmailProofByDKIM.AllowedDomains {
				ks.dkimProofAllowedDomains[d] = struct{}{}
			}
			ks.dkimProofToAddr = t.EmailProofByDKIM.ToAddr
			ks.dkimProofSubjectPrefix = t.EmailProofByDKIM.SubjectPrefix

		case *proto.RegistrationPolicy_EmailProofByOIDC:
			for _, c := range t.EmailProofByOIDC.OIDCConfig {
				o := &oidc.Client{ClientID: c.ClientID, Issuer: c.Issuer, Validity: c.Validity.Duration(), DiscoveryURL: c.DiscoveryURL}
				err := o.FetchPubKeys()
				if err != nil {
					return nil, err
				}
				oc := OIDCConfig{oidcClient: o, scope: c.Scope}
				oc.allowedDomains = make(map[string]struct{})
				for _, d := range c.AllowedDomains {
					oc.allowedDomains[d] = struct{}{}
				}
				ks.oidcProofConfig = append(ks.oidcProofConfig, oc)
			}
		case *proto.RegistrationPolicy_EmailProofBySAML:
			for _, d := range t.EmailProofBySAML.AllowedDomains {
				ks.samlProofAllowedDomains[d] = struct{}{}
			}
			url, cert, err := saml.FetchIDPInfo(t.EmailProofBySAML.IDPMetadataURL)
			if err != nil {
				return nil, err
			}
			ks.samlProofConsumerServiceURL = t.EmailProofBySAML.ConsumerServiceURL
			ks.samlProofIDPSSOURL = url
			ks.samlProofIDPCert = cert
			ks.samlProofValidity = t.EmailProofBySAML.Validity.Duration()
			key, err := kp.GetKey(t.EmailProofBySAML.ServiceProviderTLS.Certificates[0].KeyID)
			if err != nil {
				return nil, err
			}
			ks.samlProofSPKey = key

		// TODO remove this before production
		case *proto.RegistrationPolicy_InsecureSkipEmailProof:
			ks.insecureSkipEmailProof = true
		}
	}

	switch replicaStateBytes, err := ks.db.Get(coname.TableReplicaState); err {
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

	ks.sb = concurrent.NewSequenceBroadcast(ks.rs.NextIndexVerifier)

	ok := false
	if cfg.PublicAddr != "" {
		ks.publicServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(publicTLS)))
		proto.RegisterE2EKSPublicServer(ks.publicServer, ks)
		ks.publicListen, err = net.Listen("tcp", cfg.PublicAddr)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				ks.publicListen.Close()
			}
		}()
	}
	if cfg.VerifierAddr != "" {
		ks.verifierServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(verifierTLS)))
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
	if cfg.HKPAddr != "" {
		ks.hkpListen, err = tls.Listen("tcp", cfg.HKPAddr, hkpTLS)
		if err != nil {
			return nil, err
		}
		ks.hkpFront = &hkpfront.HKPFront{InsecureSkipVerify: true, Lookup: ks.Lookup, Clk: ks.clk, TLSConfig: hkpTLS}
		defer func() {
			if !ok {
				ks.hkpListen.Close()
			}
		}()
	}
	if cfg.HTTPFrontAddr != "" {
		ks.httpFrontListen, err = tls.Listen("tcp", cfg.HTTPFrontAddr, httpFrontTLS)
		if err != nil {
			return nil, err
		}
		ks.httpFront = &httpfront.HTTPFront{Lookup: ks.Lookup, Update: ks.Update, InRotation: ks.InRotation,
			IsAuthExpired: isExpired, TLSConfig: httpFrontTLS, SAMLRequest: ks.SAMLRequest, OIDCRequest: ks.OIDCRequest}
		defer func() {
			if !ok {
				ks.httpFrontListen.Close()
			}
		}()
	}

	ok = true
	return ks, nil
}

// Start makes the keyserver start handling requests (forks goroutines).
func (ks *Keyserver) Start() {
	ks.log.Start(ks.rs.NextIndexLog)
	if ks.publicServer != nil {
		go ks.publicServer.Serve(ks.publicListen)
	}
	if ks.verifierServer != nil {
		go ks.verifierServer.Serve(ks.verifierListen)
	}
	if ks.hkpFront != nil {
		ks.hkpFront.Start(ks.hkpListen)
	}
	if ks.httpFront != nil {
		ks.httpFront.Start(ks.httpFrontListen)
	}
	go ks.run()
	go ks.takeOutOfRotation()
	go ks.takeInRotation()
}

// Stop cleanly shuts down the keyserver and then returns.
func (ks *Keyserver) Stop() {
	ks.stopOnce.Do(func() {
		// FIXME: where are the listeners closed?
		if ks.publicServer != nil {
			ks.publicServer.Stop()
		}
		if ks.verifierServer != nil {
			ks.verifierServer.Stop()
		}
		if ks.hkpFront != nil {
			ks.hkpFront.Stop()
		}
		if ks.httpFront != nil {
			ks.httpFront.Stop()
		}
		close(ks.stop)
		<-ks.stopped
		ks.minEpochIntervalTimer.Stop()
		ks.maxEpochIntervalTimer.Stop()
		ks.epochProposer.Stop()
		ks.signatureProposer.Stop()
		ks.log.Stop()
		ks.signatureBroadcast.Stop()
	})
}

//InRotation indicates whether the keyserver host is in rotation
func (ks *Keyserver) InRotation() bool {
	ks.inRotationMu.Lock()
	defer ks.inRotationMu.Unlock()
	return ks.inRotation
}

// run is the CSP-style main loop of the keyserver. All code critical for safe
// persistence should be directly in run. All functions called from run should
// either interpret data and modify their mutable arguments OR interact with the
// network and disk, but not both.
func (ks *Keyserver) run() {
	defer close(ks.stopped)
	var step proto.KeyserverStep
	wb := ks.db.NewBatch()
	// @@ this loop may yield a busy loop and block commitments if the process takes up more than minEpochInternval
	for {
		select {
		case <-ks.stop:
			return
		case stepEntry := <-ks.log.WaitCommitted():
			if stepEntry.ConfChange != nil {
				ks.log.ApplyConfChange(stepEntry.ConfChange)
			}
			stepBytes := stepEntry.Data
			if stepBytes == nil {
				continue // allow logs to skip slots for indexing purposes
			}
			if err := step.Unmarshal(stepBytes); err != nil {
				log.Panicf("invalid step pb in replicated log: %s", err)
			}
			// TODO: (for throughput) allow multiple steps per log entry
			// (pipelining). Maybe this would be better implemented at the log level?
			deferredIO := ks.step(&step, &ks.rs, wb)
			ks.rs.NextIndexLog++
			wb.Put(coname.TableReplicaState, proto.MustMarshal(&ks.rs))
			if err := ks.db.Write(wb); err != nil {
				log.Panicf("sync step to db: %s", err)
			}
			wb.Reset()
			step.Reset()
			if deferredIO != nil {
				deferredIO()
			}
		case ks.leaderHint = <-ks.log.LeaderHintSet():
			ks.updateEpochProposer()
		case <-ks.minEpochIntervalTimer.C:
			ks.minEpochIntervalPassed = true
			ks.updateEpochProposer()
		case <-ks.maxEpochIntervalTimer.C:
			ks.maxEpochIntervalPassed = true
			ks.updateEpochProposer()
		}
	}
}

// step is called by run and changes the in-memory state. No i/o allowed.
func (ks *Keyserver) step(step *proto.KeyserverStep, rs *proto.ReplicaState, wb kv.Batch) (deferredIO func()) {
	// ks: &const
	// step, rs, wb: &mut
	switch step.Type.(type) {
	case *proto.KeyserverStep_Update:
		index := step.GetUpdate().Update.NewEntry.Index
		prevUpdate, err := ks.getUpdate(index, math.MaxUint64)
		if err != nil {
			log.Printf("getUpdate: %s", err)
			ks.wr.Notify(step.UID, coname.UpdateOutput{Error: fmt.Errorf("internal error")})
			return
		}
		if err := ks.verifyUpdateDeterministic(prevUpdate, step.GetUpdate()); err != nil {
			ks.wr.Notify(step.UID, coname.UpdateOutput{Error: err})
			return
		}
		latestTree := ks.merkletree.GetSnapshot(rs.LatestTreeSnapshot)

		// sanity check: compare previous version in Merkle tree vs in updates table
		prevEntryHashTree, _, err := latestTree.Lookup(index)
		if err != nil {
			ks.wr.Notify(step.UID, coname.UpdateOutput{Error: fmt.Errorf("internal error")})
			return
		}
		var prevEntryHash []byte
		if prevUpdate != nil {
			prevEntryHash = make([]byte, 32)
			sha3.ShakeSum256(prevEntryHash, prevUpdate.Update.NewEntry.Encoding)
		}
		if !bytes.Equal(prevEntryHashTree, prevEntryHash) {
			log.Fatalf("ERROR: merkle tree and DB inconsistent for index %x: %x vs %x", index, prevEntryHashTree, prevEntryHash)
		}

		var entryHash [32]byte
		sha3.ShakeSum256(entryHash[:], step.GetUpdate().Update.NewEntry.Encoding)
		newTree, err := latestTree.BeginModification()
		if err != nil {
			ks.wr.Notify(step.UID, coname.UpdateOutput{Error: fmt.Errorf("internal error")})
			return
		}
		if err := newTree.Set(index, entryHash[:]); err != nil {
			log.Printf("setting index '%x' gave error: %s", index, err)
			ks.wr.Notify(step.UID, coname.UpdateOutput{Error: fmt.Errorf("internal error")})
			return
		}
		rs.LatestTreeSnapshot = newTree.Flush(wb).Nr
		epochNr := rs.LastEpochDelimiter.EpochNumber + 1
		wb.Put(coname.TableUpdateRequests(index, epochNr), proto.MustMarshal(step.GetUpdate()))
		ks.wr.Notify(step.UID, coname.UpdateOutput{Epoch: epochNr})

		rs.PendingUpdates = true
		ks.updateEpochProposer()

		if rs.LastEpochNeedsRatification {
			// We need to wait for the last epoch to appear in the verifier log before
			// inserting this update.
			wb.Put(coname.TableUpdatesPendingRatification(rs.NextIndexLog), proto.MustMarshal(step.GetUpdate().Update))
		} else {
			// We can deliver the update to verifiers right away.
			return ks.verifierLogAppend(&proto.VerifierStep{Type: &proto.VerifierStep_Update{Update: step.GetUpdate().Update}}, rs, wb)
		}

	case *proto.KeyserverStep_EpochDelimiter:
		if step.GetEpochDelimiter().EpochNumber <= rs.LastEpochDelimiter.EpochNumber {
			return // a duplicate of this step has already been handled
		}
		rs.LastEpochDelimiter = *step.GetEpochDelimiter()
		log.Printf("epoch %d", step.GetEpochDelimiter().EpochNumber)

		rs.PendingUpdates = false
		ks.resetEpochTimers(rs.LastEpochDelimiter.Timestamp.Time())
		// rs.ThisReplicaNeedsToSignLastEpoch might already be true, if a majority
		// signed that did not include us. This will make us skip signing the last
		// epoch, but that's fine.
		rs.ThisReplicaNeedsToSignLastEpoch = true
		// However, it's not okay to see a new epoch delimiter before the previous
		// epoch has been ratified.
		if rs.LastEpochNeedsRatification {
			log.Panicf("new epoch delimiter but last epoch not ratified")
		}
		rs.LastEpochNeedsRatification = true
		ks.updateEpochProposer()
		deferredIO = ks.updateSignatureProposer

		ks.merkletree.SaveSnapshotWithEpoch(step.GetEpochDelimiter().EpochNumber, rs.LatestTreeSnapshot, wb)
		latestTree := ks.merkletree.GetSnapshot(rs.LatestTreeSnapshot)
		rootHash, err := latestTree.GetRootHash()
		if err != nil {
			log.Panicf("ks.latestTree.GetRootHash() failed: %s", err)
		}
		teh := &proto.EncodedTimestampedEpochHead{TimestampedEpochHead: proto.TimestampedEpochHead{
			Head: proto.EncodedEpochHead{EpochHead: proto.EpochHead{
				RootHash:            rootHash,
				PreviousSummaryHash: rs.PreviousSummaryHash,
				Realm:               ks.realm,
				Epoch:               step.GetEpochDelimiter().EpochNumber,
				IssueTime:           step.GetEpochDelimiter().Timestamp,
			}, Encoding: nil},
			Timestamp: step.GetEpochDelimiter().Timestamp,
		}, Encoding: nil}
		teh.Head.UpdateEncoding()
		teh.UpdateEncoding()
		if rs.PreviousSummaryHash == nil {
			rs.PreviousSummaryHash = make([]byte, 64)
		}
		sha3.ShakeSum256(rs.PreviousSummaryHash[:], teh.Head.Encoding)

		wb.Put(coname.TableEpochHeads(step.GetEpochDelimiter().EpochNumber), proto.MustMarshal(teh))

	case *proto.KeyserverStep_ReplicaSigned:
		newSEH := step.GetReplicaSigned()
		epochNr := newSEH.Head.Head.Epoch
		// get epoch head
		tehBytes, err := ks.db.Get(coname.TableEpochHeads(epochNr))
		if err != nil {
			log.Panicf("get TableEpochHeads(%d): %s", epochNr, err)
		}
		// compare epoch head to signed epoch head
		if got, want := tehBytes, newSEH.Head.Encoding; !bytes.Equal(got, want) {
			log.Panicf("replica signed different head: wanted %x, got %x", want, got)
		}

		// insert all the new signatures into the ratifications table (there should
		// actually only be one)
		newSehBytes := proto.MustMarshal(newSEH)
		for id := range newSEH.Signatures {
			// the entry might already exist in the DB (if the proposals got
			// duplicated), but it doesn't matter
			wb.Put(coname.TableRatifications(epochNr, id), newSehBytes)
		}

		deferredIO = func() {
			// First write to DB, *then* notify subscribers. That way, if subscribers
			// start listening before searching the DB, they're guaranteed to see the
			// signature: either it's already in the DB, or they'll get notified. If
			// the order was reversed, they could miss the notification but still not
			// see anything in the DB.
			ks.signatureBroadcast.Publish(epochNr, newSEH)
		}

		if epochNr != rs.LastEpochDelimiter.EpochNumber {
			break
		}
		if rs.ThisReplicaNeedsToSignLastEpoch && newSEH.Signatures[ks.replicaID] != nil {
			rs.ThisReplicaNeedsToSignLastEpoch = false
			ks.updateEpochProposer()
			// updateSignatureProposer should in general be called after writes
			// have been flushed to db, but given ThisReplicaNeedsToSignLast =
			// false we know that updateSignatureProposer will not access the db.
			ks.updateSignatureProposer()
		}
		// get all existing ratifications for this epoch
		allSignatures := make(map[uint64][]byte)
		existingRatifications, err := ks.allRatificationsForEpoch(epochNr)
		if err != nil {
			log.Panicf("allRatificationsForEpoch(%d): %s", epochNr, err)
		}
		for _, seh := range existingRatifications {
			for id, sig := range seh.Signatures {
				allSignatures[id] = sig
			}
		}
		// check whether the epoch was already ratified
		wasRatified := coname.VerifyPolicy(ks.serverAuthorized, tehBytes, allSignatures)
		if wasRatified {
			break
		}
		for id, sig := range newSEH.Signatures {
			allSignatures[id] = sig
		}
		// check whether the epoch has now become ratified
		nowRatified := coname.VerifyPolicy(ks.serverAuthorized, tehBytes, allSignatures)
		if !nowRatified {
			break
		}
		if !rs.LastEpochNeedsRatification {
			log.Panicf("%x: thought last epoch was not already ratified, but it was", ks.replicaID)
		}
		rs.LastEpochNeedsRatification = false
		ks.updateEpochProposer()
		var teh proto.EncodedTimestampedEpochHead
		err = teh.Unmarshal(tehBytes)
		if err != nil {
			log.Panicf("invalid epoch head %d (%x): %s", epochNr, tehBytes, err)
		}
		allSignaturesSEH := &proto.SignedEpochHead{
			Head:       teh,
			Signatures: allSignatures,
		}
		oldDeferredIO := deferredIO
		deferredSendEpoch := ks.verifierLogAppend(&proto.VerifierStep{Type: &proto.VerifierStep_Epoch{Epoch: allSignaturesSEH}}, rs, wb)
		deferredSendUpdates := []func(){}
		iter := ks.db.NewIterator(kv.BytesPrefix([]byte{coname.TableUpdatesPendingRatificationPrefix}))
		defer iter.Release()
		for iter.Next() {
			update := &proto.SignedEntryUpdate{}
			err := update.Unmarshal(iter.Value())
			if err != nil {
				log.Panicf("invalid pending update %x: %s", iter.Value(), err)
			}
			deferredSendUpdates = append(deferredSendUpdates, ks.verifierLogAppend(&proto.VerifierStep{Type: &proto.VerifierStep_Update{Update: update}}, rs, wb))
			wb.Delete(iter.Key())
		}
		deferredIO = func() {
			oldDeferredIO()
			// First, send the ratified epoch to verifiers
			deferredSendEpoch()
			// Then send updates that were waiting for that epoch to go out
			for _, f := range deferredSendUpdates {
				f()
			}
		}

	case *proto.KeyserverStep_VerifierSigned:
		rNew := step.GetVerifierSigned()
		for id := range rNew.Signatures {
			// Note: The signature *must* have been authenticated before being inserted
			// into the log, or else verifiers could just trample over everyone else's
			// signatures, including our own.
			dbkey := coname.TableRatifications(rNew.Head.Head.Epoch, id)
			wb.Put(dbkey, proto.MustMarshal(rNew))
		}
		ks.wr.Notify(step.UID, nil)
		return func() {
			// As above, first write to DB, *then* notify subscribers.
			ks.signatureBroadcast.Publish(rNew.Head.Head.Epoch, rNew)
		}

	case *proto.KeyserverStep_UpdateEpoch:
		if rs.LastEpochDelimiter.EpochNumber < step.GetUpdateEpoch().Delimiter.EpochNumber {
			rs.LastEpochDelimiter = *step.GetUpdateEpoch().Delimiter
		}
		rs.PendingUpdates = step.GetUpdateEpoch().Update
		ks.resetEpochTimers(rs.LastEpochDelimiter.Timestamp.Time())
		ks.updateEpochProposer()

	default:
		log.Panicf("unknown step pb in replicated log: %#v", step)
	}
	return
}

func (ks *Keyserver) takeOutOfRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for _ = range ch {
		ks.inRotationMu.Lock()
		ks.inRotation = false
		ks.inRotationMu.Unlock()
	}
}

func (ks *Keyserver) takeInRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	for _ = range ch {
		ks.inRotationMu.Lock()
		ks.inRotation = true
		ks.inRotationMu.Unlock()
	}
}

type Proposer struct {
	log      replication.LogReplicator
	clk      clock.Clock
	delay    time.Duration
	proposal replication.LogEntry

	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

func StartProposer(log replication.LogReplicator, clk clock.Clock, initialDelay time.Duration, proposal replication.LogEntry) *Proposer {
	p := &Proposer{
		log:      log,
		clk:      clk,
		delay:    initialDelay,
		proposal: proposal,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
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
		select {
		case <-timer.C:
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				select {
				case <-done:
				case <-p.stop:
					cancel()
				}
			}()
			p.log.Propose(ctx, p.proposal)
			close(done)
			timer.Reset(p.delay)
			p.delay = p.delay * 2
		case <-p.stop:
			return
		}
	}
}

// shouldEpoch returns true if this node should append an epoch delimiter to the
// log.
func (ks *Keyserver) wantEpochProposer() bool {
	return !ks.rs.LastEpochNeedsRatification && ks.leaderHint &&
		(ks.maxEpochIntervalPassed || ks.minEpochIntervalPassed && ks.rs.PendingUpdates)
}

// updateEpochProposer either starts or stops the epoch delimiter proposer as necessary.
func (ks *Keyserver) updateEpochProposer() {
	want := ks.wantEpochProposer()
	have := ks.epochProposer != nil
	if have == want {
		return
	}

	switch want {
	case true:
		ks.epochProposer = StartProposer(ks.log, ks.clk, ks.retryProposalInterval,
			replication.LogEntry{
				Data: proto.MustMarshal(&proto.KeyserverStep{Type: &proto.KeyserverStep_EpochDelimiter{EpochDelimiter: &proto.EpochDelimiter{
					EpochNumber: ks.rs.LastEpochDelimiter.EpochNumber + 1,
					Timestamp:   proto.Time(ks.clk.Now()),
				}}}),
				ConfChange: &replication.ConfChange{
					Operation: replication.ConfChangeNOP,
				},
			})
	case false:
		ks.epochProposer.Stop()
		ks.epochProposer = nil
	}
}

func (ks *Keyserver) updateSignatureProposer() {
	// invariant: do not access the db if ThisReplicaNeedsToSignLastEpoch = false
	want := ks.rs.ThisReplicaNeedsToSignLastEpoch
	have := ks.signatureProposer != nil
	if have == want {
		return
	}

	switch want {
	case true:
		tehBytes, err := ks.db.Get(coname.TableEpochHeads(ks.rs.LastEpochDelimiter.EpochNumber))
		if err != nil {
			log.Panicf("ThisReplicaNeedsToSignLastEpoch but no TEH for last epoch in db: %s", err)
		}
		var teh proto.EncodedTimestampedEpochHead
		if err := teh.Unmarshal(tehBytes); err != nil {
			log.Panicf("TableEpochHeads(%d) invalid: %s", ks.rs.LastEpochDelimiter.EpochNumber, err)
		}
		seh := &proto.SignedEpochHead{
			Head:       teh,
			Signatures: map[uint64][]byte{ks.replicaID: ed25519.Sign(ks.sehKey, tehBytes)[:]},
		}
		ks.signatureProposer = StartProposer(ks.log, ks.clk, ks.retryProposalInterval,
			replication.LogEntry{Data: proto.MustMarshal(&proto.KeyserverStep{Type: &proto.KeyserverStep_ReplicaSigned{ReplicaSigned: seh}})})
	case false:
		ks.signatureProposer.Stop()
		ks.signatureProposer = nil
	}
}

func (ks *Keyserver) resetEpochTimers(t time.Time) {
	ks.minEpochIntervalTimer.Reset(t.Add(ks.minEpochInterval).Sub(ks.clk.Now()))
	ks.maxEpochIntervalTimer.Reset(t.Add(ks.maxEpochInterval).Sub(ks.clk.Now()))
	ks.minEpochIntervalPassed = false
	ks.maxEpochIntervalPassed = false
	// caller MUST call updateEpochProposer
}

func (ks *Keyserver) allRatificationsForEpoch(epoch uint64) (map[uint64]*proto.SignedEpochHead, error) {
	iter := ks.db.NewIterator(&kv.Range{Start: coname.TableRatifications(epoch, 0), Limit: coname.TableRatifications(epoch+1, 0)})
	defer iter.Release()
	sehs := make(map[uint64]*proto.SignedEpochHead)
	for iter.Next() {
		id := binary.BigEndian.Uint64(iter.Key()[1+8 : 1+8+8])
		seh := new(proto.SignedEpochHead)
		err := seh.Unmarshal(iter.Value())
		if err != nil {
			log.Panicf("TableRatifications(%d, %d) invalid: %s", epoch, id, err)
		}
		sehs[id] = seh
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return sehs, nil
}

func genUID() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Panicf("rand.Read: %s", err)
	}
	return binary.BigEndian.Uint64(buf[:])
}
