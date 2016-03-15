package saml

import (
	"encoding/base64"
	"io/ioutil"
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
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo = "mymy"
	authnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://e2esp.yahoo.com"

	cert, err := ioutil.ReadFile("test.der")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	authnResponse.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(cert)

	payload, err := authnResponse.EncodedSignedString("test.key")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// TODO: only use byte array in DER format
	email, err := VerifySAMLResponse(payload, "test.crt", "https://e2esp.yahoo.com", "EmailAddress")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	if want, got := "foobar@yahoo-inc.com", email; got != want {
		t.Errorf("got %q (wanted %q)", got, want)
		return
	}
}
