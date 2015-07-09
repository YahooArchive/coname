package server

import (
	"crypto/tls"
	"log"
	"net"
	"sync"

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
	// FIXME: tls.Config is not serializable, replicate relevant fields
}

// Keyserver either manages or verifies a single end-to-end keyserver realm.
type Keyserver struct {
	db  *leveldb.DB
	log replication.LogReplicator

	proto.ReplicaState

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

	ks = &Keyserver{db: db, log: log, stop: make(chan struct{})}

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
	ks.log.Close()
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
	case step.EpochDelimiter != 0:
		rs.LastEpochDelimiter = step.EpochDelimiter
		rs.PendingUpdates = false
		rs.NextEpoch++
		// TODO: sign stuff, return KeyserverStep{ReplicaRatification: }
	default:
		log.Panicf("unknown step pb in replicated log: %#v", step)
	}
}
