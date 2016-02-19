package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Client represents an openid connect client
type Client struct {
	pubKeys      map[string]interface{}
	Issuer       string
	ClientID     string
	DiscoveryURL string
	Validity     time.Duration
}

// AddECDSAKey adds an ECDSA public key to the Client object
func (c *Client) AddECDSAKey(curve elliptic.Curve, x, y *big.Int, kid string) {
	if c.pubKeys == nil {
		c.pubKeys = make(map[string]interface{})
	}
	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	c.pubKeys[kid] = key
}

// AddRSAKey adds a RSA public key to the Client object
func (c *Client) AddRSAKey(n *big.Int, e int, kid string) {
	if c.pubKeys == nil {
		c.pubKeys = make(map[string]interface{})
	}
	key := &rsa.PublicKey{
		N: n,
		E: e,
	}
	c.pubKeys[kid] = key
}

// FetchPubKeys gets JWKS URI from the discovery document
// Provider public keys are then fetched from JWKS URI
// This could potentially be a goroutine running periodically
// and syncing cached public keys
func (c *Client) FetchPubKeys() error {

	type discoveryResp struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
		// other fields are ignored
	}

	type keysResp struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	dr, err := http.Get(c.DiscoveryURL)
	if err != nil {
		return err
	}
	defer dr.Body.Close()
	dj := discoveryResp{}
	json.NewDecoder(dr.Body).Decode(&dj)
	if dj.JWKSURI == "" {
		return fmt.Errorf("JWKS uri not found at %s", c.DiscoveryURL)
	}

	c.Issuer = dj.Issuer
	kr, err := http.Get(dj.JWKSURI)
	if err != nil {
		return err
	}
	defer kr.Body.Close()
	kj := keysResp{}
	json.NewDecoder(kr.Body).Decode(&kj)
	if len(kj.Keys) == 0 {
		return fmt.Errorf("No keys available at JWKS URI")
	}
	for _, obj := range kj.Keys {
		if obj.Kty == "RSA" {
			n := addOptionalPadding(obj.N)
			dn, err := base64.URLEncoding.DecodeString(n)
			if err != nil {
				return fmt.Errorf("failed to decode \"n\" value %s", obj.N)
			}
			nInt := (&big.Int{}).SetBytes(dn)
			e := addOptionalPadding(obj.E)
			de, err := base64.URLEncoding.DecodeString(e)
			if err != nil {
				return fmt.Errorf("failed to decode \"e\" value %s", obj.E)
			}
			if len(de) > 8 {
				return fmt.Errorf("Invalid length of decoded \"e\", expected <= 8 , got %d", len(de))
			}
			deBytes := make([]byte, 8-len(de), 8)
			deBytes = append(deBytes, de...)
			eInt := int(binary.BigEndian.Uint64(deBytes))
			c.AddRSAKey(nInt, eInt, obj.Kid)

		} else if obj.Kty == "EC" {
			x := addOptionalPadding(obj.X)
			dx, err := base64.URLEncoding.DecodeString(x)
			if err != nil {
				return fmt.Errorf("failed to decode \"X\" value %s", obj.X)
			}

			y := addOptionalPadding(obj.Y)
			dy, err := base64.URLEncoding.DecodeString(y)
			if err != nil {
				return fmt.Errorf("failed to decode \"Y\" value %s", obj.Y)
			}

			xInt := (&big.Int{}).SetBytes(dx)
			yInt := (&big.Int{}).SetBytes(dy)
			if obj.Crv == "P-256" {
				c.AddECDSAKey(elliptic.P256(), xInt, yInt, obj.Kid)
			}
			//TODO: add other curves
		}
	}
	return nil
}

// addOptionalPadding is a workaround for https://github.com/golang/go/issues/4237
func addOptionalPadding(s string) string {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return s
}
