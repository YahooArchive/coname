package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/agl/ed25519"
	"github.com/yahoo/coname/proto"
)

func main() {
	// This script generates CSR, private key and a verifier ID.
	// Keyserver admin will sign the CSR and provide the cert
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sv := &proto.PublicKey{PubkeyType: &proto.PublicKey_Ed25519{Ed25519: pk[:]}}
	hostname := fmt.Sprintf("verifier %x", proto.KeyID(sv))
	fmt.Println("verifier ID: " + hostname + "\nID(uint): " + strconv.FormatUint(proto.KeyID(sv), 10))
	err = ioutil.WriteFile("signing.ed25519secret", []byte(sk[:]), 0644)
	if err != nil {
		panic(err)
	}

	certTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, certTemplate, privKey)
	if err != nil {
		panic(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	// openssl req -in csr.pem -noout -text
	err = ioutil.WriteFile("csr.pem", csrPEM, 0644)
	if err != nil {
		panic(err)
	}
	keyF, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE, 0644)
	defer keyF.Close()
	if err != nil {
		panic(err)
	}
	skDer, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(keyF, &pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: make(map[string]string),
		Bytes:   skDer,
	})
	if err != nil {
		panic(err)
	}

}
