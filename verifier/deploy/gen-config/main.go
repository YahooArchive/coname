package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/yahoo/coname/proto"
)

func make_config(caCert *x509.Certificate, cert *x509.Certificate, id uint64, inputCfg *proto.VerifierConfig) {
	cfg := &proto.VerifierConfig{
		ID:                   id,
		SigningKeyID:         "signing.ed25519secret",
		Realm:                "yahoo",
		TLS:                  &proto.TLSConfig{RootCAs: [][]byte{caCert.Raw}, Certificates: []*proto.CertificateAndKeyID{{[][]byte{cert.Raw}, "tls", nil}}},
		InitialKeyserverAuth: inputCfg.InitialKeyserverAuth,
		KeyserverAddr:        inputCfg.KeyserverAddr,
	}

	configF, err := os.OpenFile("config.json", os.O_WRONLY|os.O_CREATE, 0600)
	defer configF.Close()
	if err != nil {
		log.Panic(err)
	}
	err = new(jsonpb.Marshaler).Marshal(configF, cfg)
	if err != nil {
		log.Panic(err)
	}

}

func main() {
	// input config file contains initial_keyserver_auth and keyserver_addr
	// this file will be provided by keyserver admin
	if len(os.Args) != 5 {
		fmt.Printf("usage: %s cacert cert id inputcfg\n", os.Args[0])
		return
	}
	caCertFile := os.Args[1]
	certFile := os.Args[2]
	cfgF := os.Args[4]
	id, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		log.Fatalf("Failed to convert %v to uint: %v", os.Args[3], err)
	}
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

	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read from %v: %v", certFile, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		log.Fatalf("Failed to parse PEM: %v", string(certPEM))
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse X.509 cert: %v", err)
	}

	configReader, err := os.Open(cfgF)
	if err != nil {
		log.Fatalf("Failed to open input configuration file %v: %v", cfgF, err)
	}
	cfg := &proto.VerifierConfig{}
	err = jsonpb.Unmarshal(configReader, cfg)
	if err != nil {
		log.Fatalf("Failed to parse input configuration file %v: %v", cfgF, err)
	}

	make_config(caCert, cert, uint64(id), cfg)
}
