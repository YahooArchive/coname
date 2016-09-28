package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/agl/ed25519"
	"github.com/maditya/protobuf/jsonpb"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/yahoo/coname/keyserver/kv/leveldbkv"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/verifier"
)

func main() {
	configPathPtr := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	configReader, err := os.Open(*configPathPtr)
	if err != nil {
		log.Fatalf("Failed to open configuration file: %s", err)
	}
	cfg := &proto.VerifierConfig{}
	err = jsonpb.Unmarshal(configReader, cfg)
	if err != nil {
		log.Fatalf("Failed to parse configuration file: %s", err)
	}

	leveldb, err := leveldb.OpenFile(cfg.LevelDBPath, nil)
	if err != nil {
		log.Fatalf("Couldn't open DB in directory %s: %s", cfg.LevelDBPath, err)
	}
	db := leveldbkv.Wrap(leveldb)

	server, err := verifier.Start(cfg, db, getKey)
	if err != nil {
		panic(err)
	}
	defer server.Stop()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
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
		var keyArray [ed25519.PrivateKeySize]uint8
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
