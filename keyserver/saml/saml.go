package saml

import (
	"crypto/x509"
	"fmt"

	saml "github.com/maditya/go-saml"
)

func VerifySAMLResponse(payload string, idPCert *x509.Certificate, consumerServiceURL string, attributeName string) (string, error) {
	resp, err := saml.ParseEncodedResponse(payload)
	if err != nil {
		return "", err
	}
	err = resp.Validate(&saml.ServiceProviderConfig{
		IDPCert:                     idPCert,
		AssertionConsumerServiceURL: consumerServiceURL,
	})
	if err != nil {
		return "", err
	}
	email := resp.GetAttribute(attributeName)
	if email == "" {
		return "", fmt.Errorf("Attribute %q not found or value is empty in SAML response", attributeName)
	}
	return email, nil
}

func GenerateSAMLRequest(spCert *x509.Certificate, spKey []byte, consumerServiceURL string, idPSSOURL string) (string, error) {
	sp := saml.ServiceProviderConfig{
		Cert: spCert,
		AssertionConsumerServiceURL: consumerServiceURL,
		IDPSSOURL:                   idPSSOURL,
		PrivateKey:                  spKey,
	}
	authnRequest := sp.GetAuthnRequest()
	signedXML, err := authnRequest.SignedString(sp.PrivateKey)
	if err != nil {
		return "", err
	}
	if signedXML == "" {
		return "", fmt.Errorf("signed SAML request is empty")
	}
	return signedXML, nil
}
