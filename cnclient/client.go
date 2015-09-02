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
	//"crypto/rand"
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

	name := "dmz@yahoo-inc.com"

	conn, err := grpc.Dial(realm.Addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})))
	if err != nil {
		log.Fatal(err)
	}
	publicC := proto.NewE2EKSPublicClient(conn)

	// First, do a lookup to retrieve the index
	lookup, err := publicC.Lookup(context.Background(), &proto.LookupRequest{
		UserId: name,
		// We don't care about any signatures here; the server just needs to tell us the index.
		QuorumRequirement: &proto.QuorumExpr{
			Threshold:      0,
			Candidates:     []uint64{},
			Subexpressions: []*proto.QuorumExpr{},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	index := lookup.Index

	// Then, do the actual update
	/*nonce := make([]byte, 16)
	 _, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	} */
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
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
			Index:   index,
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
	var entryHash [32]byte
	sha3.ShakeSum256(entryHash[:], entry.Encoding)
	log.Printf("entry: %x", entry.Encoding)

	proof, err := publicC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            name,
			QuorumRequirement: realm.VerificationPolicy.Quorum,
		},
		DKIMProof: []byte("X-Apparently-To: dmz@yahoo-inc.com; Wed, 02 Sep 2015 21:19:16 +0000\r\nReturn-Path: <dmz@yahoo-inc.com>\r\nReceived-SPF: pass (domain of yahoo-inc.com designates 98.139.253.104 as permitted sender)\r\nX-YMailISG: XpcSFK4WLDvVK0IqmKivwazrqOb5yjGKlwIrtdKwCpY1e1gm\r\n Aw4LJojqNWMBbKLVe7PH9I8edpBPR.yHOmEHoDl9gv6qPtWFBe2mjHb08Wst\r\n PKuRwE7wwssLfLAfvFKyu5qvi6n_rC91IECniWo.JaDyD7j2F9Es2XquhBwq\r\n BUJvR5MRyXtqgfZhp5OPwELuzIsLYWsSgyVznqCiUqLQ2ATNNXlsAFQCUqvc\r\n 3U1AY6NtHZGV_fr9aW6qBkWkQonABctPK2CnlV68jZhytAjDf3nYjWfrx7q9\r\n ii18ozYf3kWM8aYhx.PDaOSAG56Vq7pVLmPRbP1FDhWEZFuu2gXYzZibVuGJ\r\n Jz.zbSC_VIpvzM3Rb3XxA8PPNm9uVBU0yiBVieoqW4TnJSUjkLEPJFeY3cEE\r\n .0ekpqvp6JDg9f4KD9JoAgx1UxqCZWL.SiZq5bnDfpqq8vLeHkC.3fyvXOUV\r\n eK8F5ZgLbvIf0LKdtJvIEz8u2zudJJGAyAo4D2JRJTYmccsJntQZKV93jpvs\r\n yMwaKZxJiojFJ_kjXSe.PUYUsSbW2v8P0AVj9LhsD6Ddlmb30NxKnCbB5RtE\r\n UIvWfcvc3diOIT2n3F1tHXSK86ir6Ord9ifbkGVV3Ycg8Re68rPAjUm0AxXS\r\n PtsQ0EfIg3kWae.LlhbC3gH6iCzNqgPlXCco1jzS5yUbhxFCrLW5MYTHl7Fi\r\n RE.7yU61d08QvWkOR21cXajWokzypUnUPeaqhonqBTBgaww8iqOpYmZaixTs\r\n ZYLK7FGmtTedNbKWG.spiwBTORNd3jaZoGsR8G9.ldFfv21EOpRmjj8czNpc\r\n 9BVHAfSXNTmoiMg46OouHUcQVujmX1gK6lRhqZSJr.c6p5Hfn3n3Utff2bwi\r\n 7feIlLRHY3I5Fwehm41DEJAClZ5MgRr305XJ1wf8QZP9J6qUH_kf5CkoenRH\r\n hLAtmfgmW74tZfbM88Zj5Fm7kwraTW3.7EsxROj1DnzDgUPN267mYIsfcZHG\r\n PsZA.8HFkb_T9gYcL6ln_J8S4fQjTqp_ut4mvZtdl24sa6tRrdvF6gwMF6RX\r\n 0yyTjmFA_wP6f_hzMSzFYHr00oJze0g3UiAFvGvk6KrHi2Dx2l9Dc1R617Sx\r\n Ppp.HqVd4U_gJqPM63vaWtlQZelCM8NH.iuh_u1G0HgTPjNH.frt2ew7qSTC\r\n 3TizsiQ3yFVSzWmBmR.qOB1zyK1zm6Fn\r\nX-Originating-IP: [98.139.253.104]\r\nAuthentication-Results: mta2006.corp.mail.bf1.yahoo.com  from=yahoo-inc.com; domainkeys=neutral (no sig);  from=yahoo-inc.com; dkim=pass (ok)\r\nReceived: from 98.139.183.150  (EHLO mrout1-b.corp.bf1.yahoo.com) (98.139.253.104)\r\n  by mta2006.corp.mail.bf1.yahoo.com with SMTPS; Wed, 02 Sep 2015 21:19:16 +0000\r\nReceived: from omp1007.mail.ne1.yahoo.com (omp1007.mail.ne1.yahoo.com [98.138.87.7])\r\n	by mrout1-b.corp.bf1.yahoo.com (8.14.4/8.14.4/y.out) with ESMTP id t82LIeVt033471\r\n	(version=TLSv1/SSLv3 cipher=DHE-RSA-CAMELLIA256-SHA bits=256 verify=NO)\r\n	for <dmz@yahoo-inc.com>; Wed, 2 Sep 2015 14:18:40 -0700 (PDT)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=yahoo-inc.com;\r\n	s=cobra; t=1441228721;\r\n	bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=;\r\n	h=Date:From:Reply-To:To:Subject;\r\n	b=DUiQJY4/P3FmJsxMLFHcaZClRtm6QEmGuAzA1iFyYUWAOX2dOJwmfouGxJSJXy1ww\r\n	 6610vMgaqPlL7rENY5lBZrRcDfueJ1cdXhXKPR0CQHAKDPGnPfz+Hb86YZNDGBdYEO\r\n	 JyIpyzTBILEKd2+PSVT529Ai3l2/Y9yUu6gaweK8=\r\nReceived: (qmail 8244 invoked by uid 1000); 2 Sep 2015 21:18:40 -0000\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo-inc.com; s=ginc1024; t=1441228720; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; h=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding; b=HdGQw71M85g+79bX71DRS5xn/CgBXJawti4C+8NfpaCnicUv1RO6wGEQdb0O0R3gb2d0OrAjvLiCcVUWvwpWN3Eo2aUreTj1THEip3AxIdh0TApb+952cXGD52KeljVdEgFf0DroTMMcUBBZb92/hrC3I0tA1EEMBqgySPsUKKg=\r\nX-YMail-OSG: 0DtuWrwLUzvKrUMVVf5jtWesdteRmLR6oLTuKAGepU.3rTsZeR6zFmacnp0O_Dj\r\n RWZU-\r\nReceived: by 98.138.105.192; Wed, 02 Sep 2015 21:18:39 +0000 \r\nDate: Wed, 2 Sep 2015 21:18:39 +0000 (UTC)\r\nFrom: Daniel Ziegler <dmz@yahoo-inc.com>\r\nReply-To: Daniel Ziegler <dmz@yahoo-inc.com>\r\nTo: Daniel Ziegler <dmz@yahoo-inc.com>\r\nMessage-ID: <168735696.635644.1441228719331.JavaMail.yahoo@mail.yahoo.com>\r\nSubject: _YAHOO_E2E_KEYSERVER_PROOF_xzUHP903j5FiGrmg184vYSaVNEmuPyJfwtOvfoF/X/g=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\nContent-Length: 1\r\n\r\n"),
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
