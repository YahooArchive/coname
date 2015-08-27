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

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/andres-erbsen/protobuf/jsonpb"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/proto"
)

func main() {
	configPathPtr := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	configReader, err := os.Open(*configPathPtr)
	if err != nil {
		log.Fatalf("Failed to open configuration file: %s", err)
	}
	cfg := &proto.Config{}
	err = jsonpb.Unmarshal(configReader, cfg)
	if err != nil {
		log.Fatalf("Failed to parse configuration file: %s", err)
	}

	// TODO: eliminate this once we have real certs
	certFile := "ca_cert.pem"
	caCertPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatalf("couldn't read certs from %s", certFile)
	}
	caCertDER, caCertPEM := pem.Decode(caCertPEM)
	if caCertDER == nil {
		log.Fatalf("failed to parse key PEM")
	}
	caCert, err := x509.ParseCertificate(caCertDER.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	realm := cfg.Realms[0]

	conn, err := grpc.Dial(realm.Addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		log.Fatal(err)
	}
	name := "alice@example.com"
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	profile := proto.EncodedProfile{
		Profile: proto.Profile{
			Nonce: nonce,
			Keys:  map[string][]byte{"abc": []byte{1, 2, 3}, "xyz": []byte("TEST 456")},
		},
	}
	profile.UpdateEncoding()
	var commitment [64]byte
	sha3.ShakeSum256(commitment[:], profile.Encoding)
	entry := proto.EncodedEntry{
		Entry: proto.Entry{
			Version: 0,
			UpdatePolicy: &proto.AuthorizationPolicy{
				PublicKeys: make(map[uint64]*proto.PublicKey),
				Quorum: &proto.QuorumExpr{
					Threshold:      0,
					Candidates:     []uint64{},
					Subexpressions: []*proto.QuorumExpr{},
				},
			},
			ProfileCommitment: commitment[:],
		},
	}
	entry.UpdateEncoding()
	updateC := proto.NewE2EKSPublicClient(conn)
	proof, err := updateC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            name,
			QuorumRequirement: realm.VerificationPolicy.Quorum,
		},
	})
	if err != nil {
		log.Fatalf("update failed on %s: %s", realm.Addr, err)
	}
	if got, want := proof.Profile.Encoding, profile.Encoding; !bytes.Equal(got, want) {
		log.Fatalf("created profile didn't roundtrip: %x != %x", got, want)
	}
	_, err = coname.VerifyLookup(cfg, name, proof, time.Now())
	if err != nil {
		log.Fatal(err)
	}
}
