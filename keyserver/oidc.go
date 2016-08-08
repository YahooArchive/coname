package keyserver

import (
	"fmt"
	"net/url"
)

func (ks *Keyserver) OIDCRequest(domain string, uri string) (string, error) {

	for _, oc := range ks.oidcProofConfig {
		if _, ok := oc.allowedDomains[domain]; !ok {
			continue
		}
		v := url.Values{}
		v.Set("client_id", oc.oidcClient.ClientID)
		v.Set("response_type", "id_token")
		v.Set("redirect_uri", uri)
		v.Set("scope", oc.scope)
		return oc.oidcClient.Issuer + "/oauth2/request_auth?" + v.Encode(), nil

	}
	return "", fmt.Errorf("domain %q configured for OIDC auth", domain)
}
