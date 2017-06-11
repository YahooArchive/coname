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
	"crypto/tls"
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

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/concurrent"
	"github.com/yahoo/coname/keyserver/kv"
	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/keyserver/replication/raftlog"
	"github.com/yahoo/coname/keyserver/merkletree"
	raftproto "github.com/yahoo/coname/keyserver/replication/raftlog/proto"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"
	"github.com/yahoo/coname/keyserver/replication"
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
func GetKey(keyid string) (crypto.PrivateKey, error) {
	fileContents, err := ioutil.ReadFile(keyid)
	if err != nil {
		return nil, err
	}
	if path.Ext(keyid) == ".ed25519secret" {
		if got, want := len(fileContents), ed25519.PrivateKeySize; got != want {
			return nil, fmt.Errorf("ed25519 private key %s has wrong size %d (want %d)", keyid, got, want)
		}
		var keyArray [ed25519.PrivateKeySize]uint8
		copy(keyArray[:], fileContents)
		return &keyArray, nil
	} else if path.Ext(keyid) == ".vrfsecret" {
		if got, want := len(fileContents), vrf.SecretKeySize; got != want {
			return nil, fmt.Errorf("VRF private key %s has wrong size %d (want %d)", keyid, got, want)
		}
		var keyArray [vrf.SecretKeySize]uint8
		copy(keyArray[:], fileContents)
		return &keyArray, nil
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

func RunWithConfig(cfg *proto.ReplicaConfig) {
	clk := clock.New()
	wr := concurrent.NewOneShotPubSub()
	ps := concurrent.NewPublishSubscribe()

	var db kv.DB
	var replica replication.LogReplicator
	var tree *merkletree.MerkleTree
	if cfg.RaftAddr != "" {
		leveldb, err := leveldb.OpenFile(cfg.LevelDBPath, nil)
		if err != nil {
			log.Fatalf("Couldn't open DB in directory %s: %s", cfg.LevelDBPath, err)
		}
		db = leveldbkv.Wrap(leveldb)

		raftListener, err := net.Listen("tcp", cfg.RaftAddr)
		if err != nil {
			log.Fatalf("Couldn't bind to Raft node address %s: %s", cfg.RaftAddr, err)
		}
		defer raftListener.Close()
		raftTLS, err := cfg.RaftTLS.Config(GetKey)
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
					conn, err := grpc.Dial(replica.RaftAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: raftTLS.RootCAs})))
					if err != nil {
						log.Panicf("Raft GRPC dial failed: %s", err)
					}
					return raftproto.NewRaftClient(conn)
				}
			}
			log.Panicf("No raft peer %x in configuration", id)
			return nil
		}

		replicaIDs := []uint64{}
		for _, replica := range cfg.KeyserverConfig.InitialReplicas {
			replicaIDs = append(replicaIDs, replica.ID)
		}

		raft := raftlog.New(
			cfg.ReplicaID, replicaIDs, db, []byte{coname.TableReplicationLogPrefix},
			clk, cfg.RaftHeartbeat.Duration(), raftServer, dialRaftPeer,
		)
		defer raft.Stop()
		replica = raft
		tree, err = merkletree.AccessMerkleTree(db, []byte{coname.TableMerkleTreePrefix}, nil)
		if err != nil {
			log.Fatalf("Couldn't make an instance of Merkle tree: %s", err)
		}
	} else {
		log.Panicf("No configuration")
	}

	server, err := Open(cfg, &KeyserverParameters{
		DB: db,
		Log: replica,
		Clk: clk,
		WR: wr,
		PS: ps,
		Merkletree: tree,
		GetKey: GetKey,
		LookupTXT: net.LookupTXT,
	})
	if err != nil {
		log.Fatalf("Failed to initialize keyserver: %s", err)
	}
	server.Start()
	defer server.Stop()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
