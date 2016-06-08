package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os/exec"
	"testing"

	"github.com/maditya/go-saml"
)

func TestSAMLValidResponse(t *testing.T) {
	issuer := "https://idp.yahoo.com"
	authnResponse := saml.NewSignedResponse()
	authnResponse.Issuer.Url = issuer
	authnResponse.Destination = "https://e2esp.yahoo.com"
	authnResponse.Assertion.Issuer.Url = issuer
	authnResponse.AddAttribute("EmailAddress", "foobar@yahoo-inc.com")
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://e2esp.yahoo.com"

	k, err := ioutil.ReadFile("test.key")
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

	certPem, err := ioutil.ReadFile("./test.crt")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		t.Errorf("failed to PEM decode cert")
		return
	}

	authnResponse.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(certBlock.Bytes)

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	payload, err := authnResponse.EncodedSignedString(privateKey)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	email, err := VerifySAMLResponse(payload, cert, "https://e2esp.yahoo.com", "EmailAddress")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	if want, got := "foobar@yahoo-inc.com", email; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
		return
	}
}

func TestSAMLValidRequest(t *testing.T) {
	k, err := ioutil.ReadFile("test.key")
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

	certPem, err := ioutil.ReadFile("./test.crt")
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

	signedXML, err := GenerateSAMLRequest(cert, privateKey, "https://e2esp.yahoo.com", "https://idp.yahoo.com/saml/sso")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Println(signedXML)

}
