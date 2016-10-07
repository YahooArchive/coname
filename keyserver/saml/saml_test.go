package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/maditya/go-saml"
)

func TestVerifySAMLResponseValid(t *testing.T) {
	issuer := "https://idp.yahoo.com"
	authnResponse := saml.NewSignedResponse()
	authnResponse.Issuer.Url = issuer
	authnResponse.Destination = "https://e2esp.yahoo.com"
	authnResponse.Assertion.Issuer.Url = issuer
	authnResponse.AddAttribute("EmailAddress", "foobar@yahoo-inc.com")
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://e2esp.yahoo.com"

	k, err := ioutil.ReadFile("test.key")
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := pem.Decode(k)
	privateKey, err := x509.ParsePKCS1PrivateKey(kd.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPem, err := ioutil.ReadFile("./test.crt")
	if err != nil {
		t.Fatal(err)
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		t.Errorf("failed to PEM decode cert")
	}

	authnResponse.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(certBlock.Bytes)

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	payload, err := authnResponse.EncodedSignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	email, err := VerifySAMLResponse(payload, cert, "https://e2esp.yahoo.com", "EmailAddress", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "foobar@yahoo-inc.com", email; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
	}
}

func TestVerifySAMLResponseInvalid(t *testing.T) {
	issuer := "https://idp.yahoo.com"
	authnResponse := saml.NewSignedResponse()
	authnResponse.Issuer.Url = issuer
	authnResponse.Destination = "https://e2esp.yahoo.com"
	authnResponse.Assertion.Issuer.Url = issuer
	authnResponse.AddAttribute("EmailAddress", "foobar@yahoo-inc.com")
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://e2esp.yahoo.com"

	k, err := ioutil.ReadFile("test.key")
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := pem.Decode(k)
	privateKey, err := x509.ParsePKCS1PrivateKey(kd.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPem, err := ioutil.ReadFile("./test.crt")
	if err != nil {
		t.Fatal(err)
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		t.Errorf("failed to PEM decode cert")
	}

	authnResponse.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(certBlock.Bytes)

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	payload, err := authnResponse.EncodedSignedString(privateKey)
	if err != nil {
		t.Errorf(err.Error())
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = VerifySAMLResponse(payload, cert, "https://e2esp.yahoo.com", "mailAddress", 10*time.Second)
	if err == nil {
		t.Fatal(err)
	}

	_, err = VerifySAMLResponse(payload, nil, "https://e2esp.yahoo.com", "EmailAddress", 10*time.Second)
	if err == nil {
		t.Fatal(err)
	}

	_, err = VerifySAMLResponse("", cert, "https://e2esp.yahoo.com", "mailAddress", 10*time.Second)
	if err == nil {
		t.Fatal(err)
	}
	_, err = VerifySAMLResponse(payload, cert, "https://e2esp.yahoo.com", "mailAddress", -1*20*time.Second)
	if err == nil {
		t.Fatal(err)
	}
	if _, ok := err.(*ErrExpired); !ok {
		t.Errorf("expected ErrExpired, got %v", err)
	}
	if got, want := err.Error(), "assertion expired at"; !strings.HasPrefix(got, want) {
		t.Errorf("expected the error %q with a prefix %q", got, want)
	}
}

func TestGenerateSAMLRequestValid(t *testing.T) {
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

func TestGenerateSAMLRequestInvalidCert(t *testing.T) {

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

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	_, err = GenerateSAMLRequest(nil, privateKey, "https://e2esp.yahoo.com", "https://idp.yahoo.com/saml/sso")
	if err == nil {
		t.Errorf("expected GenerateSAMLRequest() to fail with nil cert, but succeeded")
	}

}

func TestGenerateSAMLRequestInvalidKey(t *testing.T) {

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

	_, err = GenerateSAMLRequest(cert, nil, "https://e2esp.yahoo.com", "https://idp.yahoo.com/saml/sso")
	if err == nil {
		t.Errorf("expected GenerateSAMLRequest() to fail with nil key, but succeeded")
	}

}

func TestFetchIDPInfo(t *testing.T) {
	// TODO: skip this test if running offline
	url, cert, err := FetchIDPInfo("https://raw.githubusercontent.com/maditya/go-saml/master/sample_metadata.xml")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := url, "https://gh.bouncer.login.yahoo.com/simplesaml/saml2/idp/SSOService.php"; got != want {
		t.Errorf("FetchIDPInfo:got %q, wanted %q", got, want)
	}
	if cert == nil {
		t.Error("FetchIDPInfo:expected a non-nil cert")
	}

	_, _, err = FetchIDPInfo("https://www.yahoo.com")
	if err == nil {
		t.Errorf("FetchIDPInfo:expected error but succeeded")
	}

	_, _, err = FetchIDPInfo("%%")
	if err == nil {
		t.Errorf("FetchIDPInfo:expected error but succeeded")
	}

}
