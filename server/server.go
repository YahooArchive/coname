package server

import (
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/replication"
	"github.com/yahoo/coname/server/replication/leveldblog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config encapsulates everything that needs to be specified about a single
// replica of one realm's keyserver to operate it.
// TODO: make this a protobuf, Unmarshal from JSON
type Config struct {
	LeveldbDir string

	UpdateAddr, LookupAddr, VerifierAddr string
	UpdateTLS, LookupTLS, VerifierTLS    *tls.Config

	MinEpochInterval, MaxEpochInterval, RetryEpochInterval time.Duration
	// FIXME: tls.Config is not serializable, replicate relevant fields
}

// Keyserver either manages or verifies a single end-to-end keyserver realm.
type Keyserver struct {
	minEpochInterval, maxEpochInterval, retryEpochInterval time.Duration

	db  *leveldb.DB
	log replication.LogReplicator
	proto.ReplicaState

	// state used for determining whether we should start a new epoch.
	// see replication.proto for explanation.
	leaderHint, canEpoch, mustEpoch       bool
	leaderHintSet                         <-chan bool
	canEpochSet, mustEpochSet, retryEpoch *time.Timer
	// proto.ReplicaState.PendingUpdates is used as well

	updateServer, lookupServer, verifierServer *grpc.Server
	updateListen, lookupListen, verifierListen net.Listener

	stop     chan struct{}
	waitStop sync.WaitGroup
}

// Open initializes a new keyserver based on cfg, reads the persistent state and
// binds to the specified ports. It does not handle input: requests will block.
func Open(cfg *Config) (ks *Keyserver, err error) {
	db, err := leveldb.OpenFile(cfg.LeveldbDir, nil)
	if err != nil {
		return nil, err
	}
	log, err := leveldblog.NewLeveldbLog(db)
	if err != nil {
		return nil, err
	}

	ks = &Keyserver{
		minEpochInterval:   cfg.MinEpochInterval,
		maxEpochInterval:   cfg.MaxEpochInterval,
		retryEpochInterval: cfg.RetryEpochInterval,
		db:                 db,
		log:                log,
		stop:               make(chan struct{}),

		// TODO: change when using actual replication
		leaderHint:    true,
		leaderHintSet: nil,

		canEpochSet:  time.NewTimer(0),
		mustEpochSet: time.NewTimer(0),
		retryEpoch:   time.NewTimer(0),
	}

	switch replicaStateBytes, err := db.Get(table_replicastate, nil); err {
	case leveldb.ErrNotFound:
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
	ks.resetEpochTimers()
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
	ks.log.Close()
	ks.db.Close()
}

// run is the CSP-style main loop of the keyserver. All code critical for safe
// persistence should be directly in run. All functions called from run should
// either interpret data and modify their mutable arguments OR interact with the
// network and disk, but not both.
func (ks *Keyserver) run() {
	var step proto.KeyserverStep
	var wb leveldb.Batch
	for {
		select {
		case <-ks.stop:
			return
		case stepBytes := <-ks.log.WaitCommitted():
			if stepBytes == nil {
				continue // allow logs to skip slots for inddexing purposes
			}
			if err := step.Unmarshal(stepBytes); err != nil {
				log.Panicf("invalid step pb in replicated log: %s", err)
			}
			ks.NextIndexLog++
			ks.step(&step, &ks.ReplicaState, &wb)
			wb.Put(table_replicastate, proto.MustMarshal(&ks.ReplicaState))
			if err := ks.db.Write(&wb, &opt.WriteOptions{Sync: true}); err != nil {
				log.Panicf("sync step to db: %s", err)
			}
			wb.Reset()
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
func (ks *Keyserver) step(step *proto.KeyserverStep, rs *proto.ReplicaState, wb *leveldb.Batch) {
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
	case step.EpochDelimiter.EpochNumber > rs.LastEpochDelimiter.EpochNumber:
		rs.LastEpochDelimiter = *step.EpochDelimiter
		rs.PendingUpdates = false
		ks.resetEpochTimers()
		// TODO: sign stuff, return KeyserverStep{ReplicaRatification: }
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
		EpochNumber: ks.ReplicaState.LastEpochDelimiter.EpochNumber + 1,
		Time:        uint64(time.Now().Unix()),
	}}))
	ks.retryEpoch.Reset(ks.retryEpochInterval)
}

func (ks *Keyserver) resetEpochTimers() {
	ks.canEpochSet.Reset(time.Unix(int64(ks.ReplicaState.LastEpochDelimiter.Time), 0).Add(ks.minEpochInterval).Sub(time.Now()))
	ks.mustEpochSet.Reset(time.Unix(int64(ks.ReplicaState.LastEpochDelimiter.Time), 0).Add(ks.maxEpochInterval).Sub(time.Now()))
	ks.retryEpoch.Stop()
	ks.canEpoch = false
	ks.mustEpoch = false
}
