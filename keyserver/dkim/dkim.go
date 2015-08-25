package dkim

import (
	"bytes"
	"fmt"
	"net/mail"
	"strings"
	"time"

	dkim "github.com/andres-erbsen/go-dkim"
)

func CheckEmailProof(dkimMail []byte, toAddr, subjectPrefix string, LookupTXT func(string) ([]string, error), now func() time.Time) (email, binding string, err error) {
	dkimHeader, err := dkim.Verify(dkimMail, LookupTXT, now)
	if err != nil {
		return "", "", err
	}

	fromHeaderSigned := false
	toHeaderSigned := false
	subjectHeaderSigned := false
	for _, hdrName := range dkimHeader.Headers {
		switch strings.ToLower(hdrName) {
		case "to":
			toHeaderSigned = true
		case "from":
			fromHeaderSigned = true
		case "subject":
			subjectHeaderSigned = true
		}
	}
	if !toHeaderSigned {
		return "", "", fmt.Errorf("the To header is not signed")
	}
	if !fromHeaderSigned {
		return "", "", fmt.Errorf("the From header is not signed")
	}
	if !subjectHeaderSigned {
		return "", "", fmt.Errorf("the Subject header is not signed")
	}

	msg, err := mail.ReadMessage(bytes.NewReader(dkimMail))
	if err != nil {
		return "", "", err
	}
	fromAddrs, err := msg.Header.AddressList("from")
	if err != nil {
		return "", "", err
	}
	if len(fromAddrs) != 1 {
		return "", "", fmt.Errorf("multiple from addresses")
	}
	email = fromAddrs[0].Address
	if !strings.HasSuffix(email, "@"+dkimHeader.Domain) {
		return "", "", fmt.Errorf("from address is not within the DKIM domain")
	}

	toAddrs, err := msg.Header.AddressList("to")
	if err != nil {
		return "", "", err
	}
	for _, dst := range toAddrs {
		addr := dst.Address
		switch {
		case addr == email:
		case addr == toAddr:
		default:
			return "", "", fmt.Errorf("unknown address %q on To line", addr)
		}
	}

	subject := msg.Header.Get("subject")
	if !strings.HasPrefix(subject, subjectPrefix) {
		return "", "", fmt.Errorf("subject line does not match the required format")
	}
	return email, subject[len(subjectPrefix):], nil
}
