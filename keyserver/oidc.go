package keyserver

import (
	"fmt"
	"net/url"
	"strings"
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
		// TODO: if this is absolutely required, generate a random one and validate it
		v.Set("nonce", "foobar") 
		// replace '+' with '%20' due to https://github.com/golang/go/issues/4013
		return oc.oidcClient.Issuer + "/oauth2/request_auth?" + strings.Replace(v.Encode(), "+", "%20", -1), nil

	}
	return "", fmt.Errorf("domain %q NOT configured for OIDC auth", domain)
}
