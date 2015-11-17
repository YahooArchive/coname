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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/andres-erbsen/protobuf/jsonpb"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/proto"
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

func main() {
	configPathPtr := flag.String("config", "clientconfig.json", "path to config file")
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

	certFile := "ca.crt.pem"
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

	clientTLS, err := realm.ClientTLS.Config(getKey)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := grpc.Dial(realm.Addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		log.Fatal(err)
	}
	publicC := proto.NewE2EKSPublicClient(conn)

	// First, do a lookup to retrieve the index
	lookup, err := publicC.Lookup(context.Background(), &proto.LookupRequest{
		UserId: name,
		// We don't care about any signatures here; the server just needs to tell us the index.
		// We could just give an empty quorum requirement if we wanted (although I guess the
		// spec actually disallows that).
		QuorumRequirement: realm.VerificationPolicy.GetQuorum(),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("looking up %s:\n", name)
	keys, err := coname.VerifyLookup(cfg, name, lookup, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if keys == nil {
		fmt.Printf("not present\n")
	} else {
		fmt.Printf("keys: %s\n", keys)
	}
	index := lookup.Index

	// Then, do the actual update
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	profile := proto.EncodedProfile{
		Profile: proto.Profile{
			Nonce: nonce,
			Keys:  map[string][]byte{"abc": []byte("foo bar"), "xyz": []byte("TEST 456")},
		},
	}
	profile.UpdateEncoding()
	var commitment [64]byte
	sha3.ShakeSum256(commitment[:], profile.Encoding)
	var version uint64
	if lookup.Entry != nil {
		version = lookup.Entry.Version + 1
	}
	entry := proto.EncodedEntry{
		Entry: proto.Entry{
			Index:   index,
			Version: version,
			UpdatePolicy: &proto.AuthorizationPolicy{
				PublicKeys: make(map[uint64]*proto.PublicKey),
				PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &proto.QuorumExpr{
					Threshold:      0,
					Candidates:     []uint64{},
					Subexpressions: []*proto.QuorumExpr{},
				},
			}},
			ProfileCommitment: commitment[:],
		},
	}
	entry.UpdateEncoding()
	var entryHash [32]byte
	sha3.ShakeSum256(entryHash[:], entry.Encoding)

	fmt.Printf("updating profile:\n")
	proof, err := publicC.Update(context.Background(), &proto.UpdateRequest{
		Update: &proto.SignedEntryUpdate{
			NewEntry:   entry,
			Signatures: make(map[uint64][]byte),
		},
		Profile: profile,
		LookupParameters: &proto.LookupRequest{
			UserId:            name,
			QuorumRequirement: realm.VerificationPolicy.GetQuorum(),
		},
		DKIMProof: []byte("X-Apparently-To: dmz@yahoo-inc.com; Mon, 31 Aug 2015 20:22:05 +0000\r\nReturn-Path: <dmz@yahoo-inc.com>\r\nReceived-SPF: pass (domain of yahoo-inc.com designates 216.145.54.155 as permitted sender)\r\nX-YMailISG: 1EhwNaYWLDv2gTUu.9nt0jxdqITV9b92O6Cwv1fdJI0Znuzw\r\n JiRKT62YsHZWJxcnlzt4SKtiChHTSAwHSy9.w97NwmcUQYqFkJkXmsqAjscY\r\n 0KW9efirs1q3YEvUtmN3BkIhbXujDW5L0Ne0YQtZnK.DF_Yi6dp7RCvfzUZf\r\n RskRPc2qP.tEMNji9_S1kSiPCtn8AwFsPHgGZtQOTtEYsTYUCsD4oEnjAJy1\r\n 332kCwDAOk1wj5l7.PwstEHF438ER_KZaMzfFq8UNrhdEwoFYZGSOfYeFV8W\r\n d2XMmN4vAJRV4D0FV9_cYwJRktzNvKqq.WddXZLuc96QR4.hxOOsq4gEEfJ8\r\n rkw8VodZEu_GlY_2lmyW8UBqmZLhO9lFuNsjfPVSVRyTxt4mMFBG_5XQudBO\r\n xudVy7LzRGiwH.3UlpR4Vl7smmSRC2bf4OrR0bZthRngty1VipzNCRVAE8Od\r\n ZjoR092JxYCF.B94f6ZF5FKqbB2QCjns3WKF0aExw.lzX8_Ral0DsXpBdan5\r\n aIU8cGBQuJBoaAjbaEanoVUXlvz0qXHLEDisvKKsc3w.igAQy01OCSik.2Gx\r\n m2XkGfeZ37mSdZhzAVKMR8eM8WkXl_O.uf7kq6vEyWXuhaMQonTjFYcdAtZX\r\n FMxFdkDTLp4bdEn1gu9JWyRYZTYnj3igBJxc0z_tIBlMrVpcf_NFpjBn1di2\r\n _sfojiKsnhUoYHwbjX7KT7yblcK8Re5Fp57g7XWIc2_tmRbY_iaiGhK0qr4x\r\n 72_hfaF0OBgArvDUPYWF50HYIP597qv1ucNyymAPVGxOx1UNOFWej494R6N1\r\n C8VTghtzKCbklLGGnmSIqPRZCZntvEsWHmmabhFwxRiTZQeu_HfN8CA_Gqoq\r\n k4qQgMbq9o22ekLsAj_jDEnUW343npUbD0XAYDOBCKuSRxZubpmXAu1HqmWL\r\n OTbpjEw8lvF_71EyG5qKVZoEiNCxXMUxia1FBp6RS_uDb4E73TgPxe1v1Ctw\r\n dzqBdg4G0DKkeMqDmDUzQUynHnonJpO4M5Bl6cdr2OfvYK7iDpPf1xeqoexb\r\n McFitNfwU6kax4VRMGahTFv2L56ovtsgV.NMuNEAwad_p3zI0kwi3OMfan9K\r\n _5pIOwQYuKc5vD.5Twq9KSOdYHGYZp_8cBv6dZ4UXvc9k1M5491nJ164VQo.\r\n v.qr6ufI2qhXdMTNxzsLw372.iYBA_5xPeT3dvaYt35sjzmjZnpN\r\nX-Originating-IP: [216.145.54.155]\r\nAuthentication-Results: mta2002.corp.mail.gq1.yahoo.com  from=yahoo-inc.com; domainkeys=neutral (no sig);  from=yahoo-inc.com; dkim=pass (ok)\r\nReceived: from 127.0.0.1  (EHLO mrout6.yahoo.com) (216.145.54.155)\r\n  by mta2002.corp.mail.gq1.yahoo.com with SMTPS; Mon, 31 Aug 2015 20:22:05 +0000\r\nReceived: from omp1018.mail.ne1.yahoo.com (omp1018.mail.ne1.yahoo.com [98.138.89.162])\r\n	by mrout6.yahoo.com (8.14.9/8.14.9/y.out) with ESMTP id t7VKLum2007505\r\n	(version=TLSv1/SSLv3 cipher=DHE-RSA-CAMELLIA256-SHA bits=256 verify=NO)\r\n	for <dmz@yahoo-inc.com>; Mon, 31 Aug 2015 13:21:56 -0700 (PDT)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=yahoo-inc.com;\r\n	s=cobra; t=1441052517;\r\n	bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=;\r\n	h=Date:From:Reply-To:To:Subject;\r\n	b=bzbQnVqgZoDSfLYqlVlyv++8CntLQ2AQJR84uPzh2OF/mnz+m+H+YfzAzYQc7b+GU\r\n	 lGgG0DX89hnWgmp4U1LlzNqwUFrhmL8muanSejVHWkrX48grrG1OwNd5z04oO0hFJE\r\n	 20ql0lI4tkgSNR7JLoedMVNm/YdrmCiHbuMj2cxg=\r\nReceived: (qmail 99407 invoked by uid 1000); 31 Aug 2015 20:21:56 -0000\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo-inc.com; s=ginc1024; t=1441052516; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; h=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding; b=r+c21Nf78CMLaL0K1FmgE/CQz70nUJyVsSgQWqu9OlGdIf2GrY9OmwueQ4xHiLu4A5Jd0CAFgxLS5ZkBkPf4xUCvaLmQOYyY+8bfM2JhuG+g2dOMmjjajNqs+iyXfyx+Ak0T2Kahom/b7cpmr5/PiAb2JpL3O0p2StukvGAolp0=\r\nX-YMail-OSG: 0DtuWrwLUzvKrUMVVf5jtWesdteRmLR6oLTuKAGepU.3rTsZeR6zFmacnp0O_Dj\r\n RWZU-\r\nReceived: by 98.138.105.210; Mon, 31 Aug 2015 20:21:55 +0000 \r\nDate: Mon, 31 Aug 2015 20:21:55 +0000 (UTC)\r\nFrom: Daniel Ziegler <dmz@yahoo-inc.com>\r\nReply-To: Daniel Ziegler <dmz@yahoo-inc.com>\r\nTo: Daniel Ziegler <dmz@yahoo-inc.com>\r\nMessage-ID: <1257428900.917316.1441052515588.JavaMail.yahoo@mail.yahoo.com>\r\nSubject: _YAHOO_E2E_KEYSERVER_PROOF_Y4ncLhJeE/qmdXlzCRp5JtgFHy4F4NbKPawk9U8vJ1E=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\nContent-Length: 1\r\n\r\n"),
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
	fmt.Printf("success\n")
}
