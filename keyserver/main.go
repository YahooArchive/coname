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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/clock"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/keyserver/replication/raftlog"
	raftproto "github.com/yahoo/coname/keyserver/replication/raftlog/proto"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"
)

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// Copied from the parsePrivateKey function in crypto/tls
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// This getKey interprets key IDs as paths, and loads private keys from the
// specified file
func getKey(keyid string) (crypto.PrivateKey, error) {
	fileContents, err := ioutil.ReadFile(keyid)
	if err != nil {
		return nil, err
	}
	if path.Ext(keyid) == ".ed25519secret" {
		if got, want := len(fileContents), ed25519.PrivateKeySize; got != want {
			return nil, fmt.Errorf("ed25519 private key %s has wrong size %d (want %d)", keyid, got, want)
		}
		return fileContents, nil
	} else if path.Ext(keyid) == ".vrfsecret" {
		if got, want := len(fileContents), vrf.SecretKeySize; got != want {
			return nil, fmt.Errorf("VRF private key %s has wrong size %d (want %d)", keyid, got, want)
		}
		return fileContents, nil
	} else {
		keyPEM := fileContents
		var keyDER *pem.Block
		for {
			keyDER, keyPEM = pem.Decode(keyPEM)
			if keyDER == nil {
				return nil, fmt.Errorf("failed to parse key PEM in %s", keyid)
			}
			if keyDER.Type == "PRIVATE KEY" || strings.HasSuffix(keyDER.Type, " PRIVATE KEY") {
				break
			}
		}
		return parsePrivateKey(keyDER.Bytes)
	}
}

func majority(nReplicas int) int {
	return nReplicas/2 + 1
}

func RunWithConfig(cfg *proto.ReplicaConfig) {
	// TODO: since we only want to support precisely this ratification policy,
	// this should be moved into server.go
	ratificationPolicy := &proto.AuthorizationPolicy{
		PublicKeys: make(map[uint64]*proto.PublicKey),
		Quorum: &proto.QuorumExpr{
			Threshold: uint32(majority(len(cfg.KeyserverConfig.InitialReplicas))),
		},
	}
	replicaIDs := []uint64{}
	for _, replica := range cfg.KeyserverConfig.InitialReplicas {
		replicaIDs = append(replicaIDs, replica.ID)
		replicaExpr := &proto.QuorumExpr{
			Threshold: 1,
		}
		for _, pk := range replica.PublicKeys {
			pkid := proto.KeyID(pk)
			ratificationPolicy.PublicKeys[pkid] = pk
			replicaExpr.Candidates = append(replicaExpr.Candidates, pkid)
		}
		ratificationPolicy.Quorum.Subexpressions = append(ratificationPolicy.Quorum.Subexpressions, replicaExpr)
	}

	leveldb, err := leveldb.OpenFile(cfg.LevelDBPath, nil)
	if err != nil {
		log.Fatalf("Couldn't open DB in directory %s: %s", cfg.LevelDBPath, err)
	}
	db := leveldbkv.Wrap(leveldb)

	clk := clock.New()

	raftListener, err := net.Listen("tcp", cfg.RaftAddr)
	if err != nil {
		log.Fatalf("Couldn't bind to Raft node address %s: %s", cfg.RaftAddr, err)
	}
	defer raftListener.Close()
	raftTLS, err := cfg.RaftTLS.Config(getKey)
	if err != nil {
		log.Fatalf("Bad Raft TLS configuration: %s", err)
	}
	raftCreds := credentials.NewTLS(raftTLS)
	raftServer := grpc.NewServer(grpc.Creds(raftCreds))
	go raftServer.Serve(raftListener)
	defer raftServer.Stop()

	dialRaftPeer := func(id uint64) raftproto.RaftClient {
		// TODO use current, not initial, config
		for _, replica := range cfg.KeyserverConfig.InitialReplicas {
			if replica.ID == id {
				conn, err := grpc.Dial(replica.RaftAddr, grpc.WithTransportCredentials(raftCreds))
				if err != nil {
					log.Panicf("Raft GRPC dial failed: %s", err)
				}
				return raftproto.NewRaftClient(conn)
			}
		}
		log.Panicf("No raft peer %x in configuration", id)
		return nil
	}

	raft := raftlog.New(
		cfg.ReplicaID, replicaIDs, db, []byte{tableReplicationLogPrefix},
		clk, cfg.RaftHeartbeat.Duration(), raftServer, dialRaftPeer,
	)
	defer raft.Stop()

	server, err := Open(cfg, db, raft, ratificationPolicy, clk, getKey, net.LookupTXT)
	if err != nil {
		log.Fatalf("Failed to initialize keyserver: %s", err)
	}
	server.Start()
	defer server.Stop()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
