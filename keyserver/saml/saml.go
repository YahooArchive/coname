package saml

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	saml "github.com/maditya/go-saml"
)

func VerifySAMLResponse(payload string, idPCert *x509.Certificate, consumerServiceURL string, attributeName string, validity time.Duration) (string, error) {
	resp, err := saml.ParseEncodedResponse(payload)
	if err != nil {
		return "", err
	}
	err = resp.Validate(&saml.ServiceProviderConfig{
		IDPCert:                     idPCert,
		AssertionConsumerServiceURL: consumerServiceURL,
		AssertionValidity:           validity,
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

func GenerateSAMLRequest(spCert *x509.Certificate, spKey crypto.PrivateKey, consumerServiceURL string, idPSSOURL string) (string, error) {
	sp := saml.ServiceProviderConfig{
		Cert: spCert,
		AssertionConsumerServiceURL: consumerServiceURL,
		IDPSSOURL:                   idPSSOURL,
		PrivateKey:                  spKey,
	}
	authnRequest := sp.GetAuthnRequest()
	b64SignedXML, err := authnRequest.CompressedEncodedSignedString(sp.PrivateKey)
	if err != nil {
		return "", err
	}

	// url encode the payload
	v := url.Values{}
	v.Set("", b64SignedXML)
	ue := v.Encode()[1:] // strip the leading "="

	return ue, nil
}

func FetchIDPInfo(metadataURL string) (string, *x509.Certificate, error) {
	c := http.Client{Timeout: 10 * time.Second}
	url, err := url.Parse(metadataURL)
	if err != nil {
		return "", nil, err
	}
	resp, err := c.Do(&http.Request{URL: url})
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	metadata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	return saml.ParseIDPMetadata(metadata)
}
