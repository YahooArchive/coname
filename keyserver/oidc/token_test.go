package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestFetchPubKeys(t *testing.T) {

	cases := []struct {
		url   string
		valid bool
		out   error
	}{
		{"https://accounts.google.com/.well-known/openid-configuration", true, nil},
		{"https://mail.yahoo.com/.well-known/openid-configuration", false, fmt.Errorf("JWKS uri not found at https://mail.yahoo.com/.well-known/openid-configuration")},
	}
	for _, tc := range cases {
		c := &Client{DiscoveryURL: tc.url}
		err := c.FetchPubKeys()
		if tc.valid {
			if err != nil {
				t.Errorf("FetchPubKeys() failed for (%s), (%v)", tc.url, err)
			}
		} else {
			if err == nil || err.Error() != tc.out.Error() {
				t.Errorf("FetchPubKeys() - wanted (%v), got (%v)", tc.out, err)
			}
		}
	}

}

func TestIDToken(t *testing.T) {

	email := "mytest1@yahoo.com"
	aud := "foo"
	iss := "https://api.login.yahoo.com"
	iat := time.Now().Unix()
	exp := time.Now().Add(time.Minute * 30).Unix()
	validity := time.Second * 30
	kid := "111"

	time.Sleep(time.Second * 2) // required for validity negative test case

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("keygen failed - %v", err)
	}
	cases := []struct {
		aud      string
		exp      int64
		email    string
		emailVrf bool
		iss      string
		kid      string
		validity time.Duration
		valid    bool
	}{
		{aud, exp, email, true, iss, kid, validity, true},
		{"foobar", exp, email, true, iss, kid, validity, false},
		{aud, time.Now().Unix() - 1, email, true, iss, kid, validity, false},
		{aud, exp, "mytest2@yahoo.com", true, iss, kid, validity, false},
		{aud, exp, email, false, iss, kid, validity, false},
		{aud, exp, email, true, "https://new.api.login.yahoo.com", kid, validity, false},
		{aud, exp, email, true, iss, "222", validity, false},
		{aud, exp, email, true, iss, kid, time.Second, false},
	}

	for i, tc := range cases {
		c := &Client{ClientID: aud, Issuer: iss, Validity: tc.validity}
		c.AddECDSAKey(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y, kid)
		claims := map[string]interface{}{
			"aud":            tc.aud,
			"email":          tc.email,
			"email_verified": tc.emailVrf,
			"exp":            tc.exp,
			"iat":            iat,
			"iss":            tc.iss,
		}
		token := jwt.New(jwt.SigningMethodES256)
		token.Claims = claims
		token.Header["kid"] = tc.kid
		tokStr, err := token.SignedString(key)
		if err != nil {
			t.Errorf("token signing failed - %v", err)
		}
		emailVerified, err := c.VerifyIDToken(tokStr)
		if tc.valid {
			fmt.Println(tokStr)
			if err != nil {
				t.Errorf("VerifyIDToken() failed - %v", err)
			}
			if want, got := email, emailVerified; got != want {
				t.Errorf("email id mismatch, got %q (wanted %q)", got, want)
			}
		} else {
			if err == nil && email == emailVerified {
				t.Errorf("Negative test case failed, id: %d, token: (%v), validity: %v", i, token, tc.validity)
			}
		}

	}
}
func TestIDTokenInvalidKey(t *testing.T) {

	email := "mytest1@yahoo.com"
	aud := "foo"
	iss := "https://api.login.yahoo.com"
	iat := time.Now().Unix()
	exp := time.Now().Add(time.Minute * 30).Unix()
	validity := time.Second * 30
	kid := "111"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("keygen failed - %v", err)
	}

	keyBogus, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("keygen failed - %v", err)
	}

	c := &Client{ClientID: aud, Issuer: iss, Validity: validity}
	c.AddECDSAKey(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y, kid)
	claims := map[string]interface{}{
		"aud":            aud,
		"email":          email,
		"email_verified": true,
		"exp":            exp,
		"iat":            iat,
		"iss":            iss,
	}
	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = claims
	token.Header["kid"] = kid
	tokStr, err := token.SignedString(keyBogus)
	if err != nil {
		t.Errorf("token signing failed - %v", err)
	}
	emailVerified, err := c.VerifyIDToken(tokStr)
	if err == nil && emailVerified == email {
		t.Error("validated a token signed with a bogus key")
	}
}
