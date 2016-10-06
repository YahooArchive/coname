package keyserver

import (
	"testing"

	"github.com/yahoo/coname/keyserver/oidc"
)

func TestOIDCRequest(t *testing.T) {
	c := "foo"
	i := "https://bar.com"
	d := "https://example.com"
	s := "read"
	expURL := "https://bar.com/oauth2/request_auth?client_id=foo&nonce=foobar&redirect_uri=ks.com&response_type=id_token&scope=read"
	o := &oidc.Client{ClientID: c, Issuer: i, DiscoveryURL: d}
	oc := OIDCConfig{oidcClient: o, scope: s}
	oc.allowedDomains = make(map[string]struct{})
	for _, d := range []string{"foomail.com", "barmail.com"} {
		oc.allowedDomains[d] = struct{}{}
	}
	ks := Keyserver{oidcProofConfig: []OIDCConfig{oc}}
	url, err := ks.OIDCRequest("foomail.com", "ks.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := url, expURL; got != want {
		t.Fatalf("url: got %q but wanted %q", got, want)
	}

	url, err = ks.OIDCRequest("foomailinvalid.com", "ks.com")
	if err == nil {
		t.Fatalf("OIDCRequest expected to fail, but got a url %q", url)
	}
	if got, want := err.Error(), "domain \"foomailinvalid.com\" NOT configured for OIDC auth"; got != want {
		t.Fatalf("OIDCRequest expected to fail with err %q , got %q", want, got)
	}

	url, err = ks.OIDCRequest("", "ks.com")
	if err == nil {
		t.Fatalf("OIDCRequest expected to fail, but got a url %q", url)
	}
	if got, want := err.Error(), "domain \"\" NOT configured for OIDC auth"; got != want {
		t.Fatalf("OIDCRequest expected to fail with err %q , got %q", want, got)
	}

}
