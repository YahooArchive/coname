package keyserver

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os/exec"
	"strings"
	"testing"
)

func TestSAMLRequest(t *testing.T) {
	ks := Keyserver{}
	_, err := ks.SAMLRequest()
	if err == nil {
		t.Fatal("expected SAMLRequest() to fail, but succeeded")
	}

	domains := make(map[string]struct{})
	for _, d := range []string{"foomail.com", "barmail.com"} {
		domains[d] = struct{}{}
	}
	ks = Keyserver{samlProofAllowedDomains: domains}
	_, err = ks.SAMLRequest()
	if err == nil {
		t.Fatal("expected SAMLRequest() to fail, but succeeded")
	}
	k, err := ioutil.ReadFile("saml/test.key")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	kd, _ := pem.Decode(k)
	privateKey, err := x509.ParsePKCS1PrivateKey(kd.Bytes)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	certPem, err := ioutil.ReadFile("saml/test.crt")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		t.Errorf("failed to PEM decode cert")
		return
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}
	ks = Keyserver{samlProofAllowedDomains: domains, samlProofIDPCert: cert, samlProofSPKey: privateKey, samlProofConsumerServiceURL: "https://ks.alice.wonderland", samlProofIDPSSOURL: "https://idp.bob"}
	req, err := ks.SAMLRequest()
	if err != nil {
		t.Fatal(err)
	}
	p := "https://idp.bob?SAMLRequest="
	if !strings.HasPrefix(req, p) {
		t.Errorf("got request url %q, expected it to begin with %q", req, p)
	}
}
