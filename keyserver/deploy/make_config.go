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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/agl/ed25519"
	"github.com/andres-erbsen/protobuf/jsonpb"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"
)

const (
	publicPort      = 4625
	verifierPort    = 4626
	hkpPort         = 11371
	raftPort        = 9807
	realm           = "yahoo"
	dkimProofPrefix = "_YAHOO_E2E_KEYSERVER_PROOF_"
	dkimProofDomain = "yahoo-inc.com"
)

func newSerial(rnd io.Reader) (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rnd, serialNumberLimit)
}

func make_cert(caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey, hostname string) (tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := newSerial(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	certTemplate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: hostname},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2 /* years */, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		certTemplate.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privKey, Leaf: cert}, nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("usage: %s cacert cakey host0 host1 host2...\n", os.Args[0])
		return
	}

	caCertFile := os.Args[1]
	caKeyFile := os.Args[2]
	caCertPem, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read from %v: %v", caCertFile, err)
	}
	caCertBlock, _ := pem.Decode(caCertPem)
	if caCertBlock == nil {
		log.Fatalf("Failed to parse PEM: %v", string(caCertPem))
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse X.509 cert: %v", err)
	}

	caKeyPem, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		log.Fatalf("Failed to read from %v: %v", caKeyFile, err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPem)
	if caKeyBlock == nil {
		log.Fatalf("Failed to parse PEM: %v", string(caKeyPem))
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse EC private key: %v", err)
	}

	hosts := os.Args[3:]

	vrfPublic, vrfSecret, err := vrf.GenerateKey(rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	var pks []*[ed25519.PublicKeySize]byte
	var sks []*[ed25519.PrivateKeySize]byte
	var replicas []*proto.Replica
	for _, host := range hosts {
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Panic(err)
		}
		pks = append(pks, pk)
		sks = append(sks, sk)
		ppk := &proto.PublicKey{
			PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pk[:]},
		}
		replicas = append(replicas, &proto.Replica{
			ID:         proto.KeyID(ppk),
			PublicKeys: []*proto.PublicKey{ppk},
			RaftAddr:   fmt.Sprintf("%s:%d", host, raftPort),
		})
	}

	// TODO: non-silly way of generating ID
	var serverID [8]byte
	sha3.ShakeSum128(serverID[:], vrfPublic)
	ksConfig := proto.KeyserverConfig{
		Realm:    realm,
		ServerID: binary.LittleEndian.Uint64(serverID[:]),
		VRFKeyID: "vrf.vrfsecret",

		MinEpochInterval:      proto.DurationStamp(1 * time.Second),
		MaxEpochInterval:      proto.DurationStamp(1 * time.Minute),
		ProposalRetryInterval: proto.DurationStamp(1 * time.Second),

		InitialReplicas:          replicas,
		EmailProofToAddr:         "TODO@example.com",
		EmailProofSubjectPrefix:  dkimProofPrefix,
		EmailProofAllowedDomains: []string{dkimProofDomain},

		// TODO get rid of this
		InsecureSkipEmailProof: true,
	}

	var cfgs []*proto.ReplicaConfig
	for i, host := range hosts {
		pk, sk := pks[i], sks[i]
		pked := &proto.PublicKey{PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pk[:]}}
		replicaID := proto.KeyID(pked)

		cert, err := make_cert(caCert, caKey, host)
		if err != nil {
			log.Fatal(err)
		}
		pcerts := []*proto.CertificateAndKeyID{{cert.Certificate, "tls.key.pem", nil}}
		heartbeat := proto.DurationStamp(1 * time.Second)
		cfg := &proto.ReplicaConfig{
			KeyserverConfig:     ksConfig,
			SigningKeyID:        "signing.ed25519secret",
			ReplicaID:           replicaID,
			PublicAddr:          fmt.Sprintf("%s:%d", host, publicPort),
			VerifierAddr:        fmt.Sprintf("%s:%d", host, verifierPort),
			HKPAddr:             fmt.Sprintf("%s:%d", host, hkpPort),
			RaftAddr:            fmt.Sprintf("%s:%d", host, raftPort),
			PublicTLS:           proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			VerifierTLS:         proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			HKPTLS:              proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, ClientCAs: [][]byte{caCert.Raw}, ClientAuth: proto.REQUIRE_AND_VERIFY_CLIENT_CERT},
			RaftTLS:             proto.TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}},
			LevelDBPath:         "db", // TODO
			RaftHeartbeat:       heartbeat,
			ClientTimeout:       proto.DurationStamp(1 * time.Minute),
			LaggingVerifierScan: 1000,
		}
		cfgs = append(cfgs, cfg)

		if _, err := os.Stat(host + "/"); os.IsNotExist(err) {
			os.Mkdir(host, 0700)
		}
		tlsKeyF, err := os.OpenFile(path.Join(host, "tls.key.pem"), os.O_WRONLY|os.O_CREATE, 0600)
		defer tlsKeyF.Close()
		if err != nil {
			log.Panic(err)
		}
		pkDer, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			log.Panic(err)
		}
		err = pem.Encode(tlsKeyF, &pem.Block{
			Type:    "EC PRIVATE KEY",
			Headers: make(map[string]string),
			Bytes:   pkDer,
		})
		if err != nil {
			log.Panic(err)
		}

		err = ioutil.WriteFile(path.Join(host, "vrf.vrfsecret"), vrfSecret[:], 0600)
		if err != nil {
			log.Panic(err)
		}

		err = ioutil.WriteFile(path.Join(host, "signing.ed25519secret"), sk[:], 0600)
		if err != nil {
			log.Panic(err)
		}

		configF, err := os.OpenFile(path.Join(host, "config.json"), os.O_WRONLY|os.O_CREATE, 0600)
		defer configF.Close()
		if err != nil {
			log.Panic(err)
		}
		err = new(jsonpb.Marshaler).Marshal(configF, cfg)
		if err != nil {
			log.Panic(err)
		}
	}

	err = ioutil.WriteFile("vrf.vrfpublic", vrfPublic[:], 0644)
	if err != nil {
		log.Panic(err)
	}

	clientCert, err := make_cert(caCert, caKey, "client")
	if err != nil {
		log.Fatal(err)
	}

	verificationPolicy := &proto.AuthorizationPolicy{
		PublicKeys: make(map[uint64]*proto.PublicKey),
		PolicyType: &proto.AuthorizationPolicy_Quorum{
			&proto.QuorumExpr{Threshold: uint32(majority(len(hosts)))},
		},
	}
	replicaIDs := []uint64{}
	for i, cfg := range cfgs {
		replicaIDs = append(replicaIDs, cfg.ReplicaID)
		pk := &proto.PublicKey{
			PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pks[i][:]},
		}
		pkid := proto.KeyID(pk)
		verificationPolicy.PublicKeys[pkid] = pk
		replicaExpr := &proto.QuorumExpr{
			Threshold:  1,
			Candidates: []uint64{pkid},
		}
		verificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum).Quorum.Subexpressions = append(verificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum).Quorum.Subexpressions, replicaExpr)
	}
	clientConfig := &proto.Config{
		Realms: []*proto.RealmConfig{
			&proto.RealmConfig{
				Domains:            []string{"yahoo-inc.com"},
				Addr:               cfgs[0].PublicAddr,
				VRFPublic:          vrfPublic[:],
				VerificationPolicy: verificationPolicy,
				EpochTimeToLive:    proto.DurationStamp(3 * time.Minute),
				TreeNonce:          nil,
				ClientTLS: &proto.TLSConfig{
					RootCAs:      [][]byte{caCert.Raw},
					Certificates: []*proto.CertificateAndKeyID{{clientCert.Certificate, "client.key.pem", nil}},
				},
			},
		},
	}
	clientConfigF, err := os.OpenFile("clientconfig.json", os.O_WRONLY|os.O_CREATE, 0644)
	defer clientConfigF.Close()
	if err != nil {
		log.Panic(err)
	}
	err = new(jsonpb.Marshaler).Marshal(clientConfigF, clientConfig)
	if err != nil {
		log.Panic(err)
	}

	clientKeyF, err := os.OpenFile("client.key.pem", os.O_WRONLY|os.O_CREATE, 0644)
	defer clientKeyF.Close()
	if err != nil {
		log.Panic(err)
	}
	skDer, err := x509.MarshalECPrivateKey(clientCert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		log.Panic(err)
	}
	err = pem.Encode(clientKeyF, &pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: make(map[string]string),
		Bytes:   skDer,
	})
	if err != nil {
		log.Panic(err)
	}
}

func majority(nReplicas int) int {
	return nReplicas/2 + 1
}
