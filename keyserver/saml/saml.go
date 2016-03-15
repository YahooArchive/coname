package saml

import (
	"fmt"
	saml "github.com/maditya/go-saml"
)

func VerifySAMLResponse(payload string, idPCertPath string, consumerServiceURL string, attributeName string) (string, error) {
	resp, err := saml.ParseEncodedResponse(payload)
	if err != nil {
		return "", err
	}
	// TODO: use byte array for cert
	sp := saml.ServiceProviderSettings{
		IDPPublicCertPath:           idPCertPath,
		AssertionConsumerServiceURL: consumerServiceURL,
	}
	sp.Init()
	err = resp.Validate(&sp)
	if err != nil {
		return "", err
	}
	email := resp.GetAttribute(attributeName)
	if email == "" {
		return "", fmt.Errorf("Attribute %q not found or value is empty in SAML response", attributeName)
	}
	return email, nil
}
