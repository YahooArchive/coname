package proto

import (
	"crypto"
	"errors"
	"testing"

	"github.com/andres-erbsen/tlstestutil"
)

func TestConfig(t *testing.T) {

	caCert, _, caKey := tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, caCert, caKey, "127.0.0.1", nil)
	st := [32]byte{1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2}
	badST := [2]byte{1, 2}
	errGetKey := errors.New("test error")
	getKey := func(keyid string) (crypto.PrivateKey, error) {
		switch keyid {
		case "tls":
			return cert.PrivateKey, nil
		case "badTLS":
			return nil, errGetKey
		case "stk":
			return st, nil
		case "badst1":
			return badST, nil
		case "badst2":
			return nil, errGetKey
		case "badst3":
			return nil, nil
		default:
			panic("unknown key requested in tests [" + keyid + "]")
		}
	}

	pcerts := []*CertificateAndKeyID{{cert.Certificate, "tls", nil}}

	goodTLS := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}}
	_, err := goodTLS.Config(getKey)
	if err != nil {
		t.Fatal(err)
	}

	pcertsBad := []*CertificateAndKeyID{{cert.Certificate, "badTLS", nil}}
	cfgBadKey := &TLSConfig{Certificates: pcertsBad, RootCAs: [][]byte{caCert.Raw}}
	_, err = cfgBadKey.Config(getKey)
	if err != errGetKey {
		t.Errorf("expected error: %v, got %v", errGetKey, err)
	}

	cfgSessionTkt := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, SessionTicketKeyID: "stk"}
	_, err = cfgSessionTkt.Config(getKey)
	if err != nil {
		t.Fatal(err)
	}

	cfgBadSessionTkt1 := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, SessionTicketKeyID: "badst1"}
	_, err = cfgBadSessionTkt1.Config(getKey)
	if err == nil {
		t.Errorf("expected error %q, got nil", "SessionTicketKey must be a [32]byte...")
	}

	cfgBadSessionTkt2 := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, SessionTicketKeyID: "badst2"}
	_, err = cfgBadSessionTkt2.Config(getKey)
	if err != errGetKey {
		t.Errorf("expected error: %v, got %v", errGetKey, err)
	}

	cfgBadSessionTkt3 := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, SessionTicketKeyID: "badst3"}
	_, err = cfgBadSessionTkt3.Config(getKey)
	if err == nil {
		t.Errorf("expected error %q, got nil", "SessionTicketKey must be a [32]byte...")
	}

	cfgCipherSuites := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, CipherSuites: []CipherSuite{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_RC4_128_SHA}}
	_, err = cfgCipherSuites.Config(getKey)
	if err != nil {
		t.Fatal(err)
	}

	cfgCurvePref := &TLSConfig{Certificates: pcerts, RootCAs: [][]byte{caCert.Raw}, CurvePreferences: []CurveID{P256, P384, P521}}
	_, err = cfgCurvePref.Config(getKey)
	if err != nil {
		t.Fatal(err)
	}
}
