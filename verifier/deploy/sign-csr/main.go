package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

func newSerial(rnd io.Reader) (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rnd, serialNumberLimit)
}

func sign_csr(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, csr *x509.CertificateRequest) {
	serial, err := newSerial(rand.Reader)
	if err != nil {
		panic(err)
	}
	certTemplate := &x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2 /* years */, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey.(*ecdsa.PublicKey), caKey)
	if err != nil {
		panic(err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// openssl x509 -in cert.pem  -noout -text
	err = ioutil.WriteFile("cert.pem", certPem, 0644)
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("usage: %s cacert cakey csr\n", os.Args[0])
		return
	}
	caCertFile := os.Args[1]
	caKeyFile := os.Args[2]
	csrFile := os.Args[3]
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
	csrPem, err := ioutil.ReadFile(csrFile)
	if err != nil {
		log.Fatalf("Failed to read from %v: %v", csrPem, err)
	}
	csrBlock, _ := pem.Decode(csrPem)
	if csrBlock == nil {
		log.Fatalf("Failed to parse PEM: %v", string(csrPem))
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CSR: %v", err)
	}
	sign_csr(caKey, caCert, csr)

}
