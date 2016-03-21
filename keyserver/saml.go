package keyserver

import (
	"encoding/json"
	"fmt"

	"github.com/yahoo/coname/keyserver/saml"
)

type SAMLReq struct {
	Payload   string
	IDPSSOURL string
}

func (ks *Keyserver) SAMLRequest() ([]byte, error) {
	if len(ks.samlProofAllowedDomains) == 0 {
		return nil, fmt.Errorf("No domains configured for SAML auth")
	}
	payload, err := saml.GenerateSAMLRequest(ks.samlProofIDPCert, ks.samlProofSPKey, ks.samlProofConsumerServiceURL, ks.samlProofIDPSSOURL)
	if err != nil {
		return nil, err
	}
	reqJSON := &SAMLReq{Payload: payload, IDPSSOURL: ks.samlProofIDPSSOURL}
	reqStr, err := json.Marshal(reqJSON)
	if err != nil {
		return nil, err
	}
	return reqStr, nil

}
