package keyserver

import (
	"fmt"
	"github.com/yahoo/coname/keyserver/saml"
)

type SAMLReq struct {
	Payload   string
	IDPSSOURL string
}

// SAMLRequest constructs the redirect URL with SAMLRequest
// as a query string parameter
func (ks *Keyserver) SAMLRequest() (string, error) {
	if len(ks.samlProofAllowedDomains) == 0 {
		return "", fmt.Errorf("No domains configured for SAML auth")
	}
	payload, err := saml.GenerateSAMLRequest(ks.samlProofIDPCert, ks.samlProofSPKey, ks.samlProofConsumerServiceURL, ks.samlProofIDPSSOURL)
	if err != nil {
		return "", err
	}
	return ks.samlProofIDPSSOURL + "?SAMLRequest=" + payload, nil
}
