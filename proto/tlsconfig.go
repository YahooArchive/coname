package proto

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func certPool(certs [][]byte) (*x509.CertPool, error) {
	ret := x509.NewCertPool()
	for _, der := range certs {
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		ret.AddCert(crt)
	}
	return ret, nil
}

func (m *TLSConfig) Config(getKey func(string) (crypto.PrivateKey, error)) (cfg *tls.Config, err error) {
	cfg = new(tls.Config)
	for _, t := range m.Certificates {
		key, err := getKey(t.KeyId)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = append(cfg.Certificates, tls.Certificate{
			Certificate: t.Certificate,
			PrivateKey:  key,
			OCSPStaple:  t.OCSPStaple,
		})
	}
	cfg.RootCAs, err = certPool(m.RootCas)
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = m.NextProtos
	cfg.ServerName = m.ServerName
	cfg.ClientAuth = tls.ClientAuthType(m.ClientAuth)
	cfg.ClientCAs, err = certPool(m.ClientCas)
	if err != nil {
		return nil, err
	}
	for _, cs := range m.CipherSuites {
		cfg.CipherSuites = append(cfg.CipherSuites, uint16(cs))
	}
	cfg.PreferServerCipherSuites = m.PreferServerCipherSuites
	cfg.SessionTicketsDisabled = !m.SessionTicketsEnabled
	stk, err := getKey(m.SessionTicketKeyId)
	if err != nil {
		return nil, err
	}
	stk32, ok := stk.([32]byte)
	if !ok {
		return nil, fmt.Errorf("SessionTicketKey must be [32]byte, got %T (%v)", stk, stk)
	}
	cfg.SessionTicketKey = stk32
	cfg.MinVersion = uint16(m.MinVersion)
	cfg.MaxVersion = uint16(m.MaxVersion)
	for _, cid := range m.CurvePreferences {
		cfg.CurvePreferences = append(cfg.CurvePreferences, tls.CurveID(cid))
	}
	return cfg, nil
}
