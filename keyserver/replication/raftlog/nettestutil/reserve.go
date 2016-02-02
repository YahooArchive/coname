package nettestutil

import (
	"net"
	"testing"
)

var reservedListeners = make(map[string]net.Listener)

// ReserveListener allocates a port to be used by this application by binding
// to it. The listener is kept in a global pool, to be claimed using Listen.
// The address of the listener is returned.
func ReserveListener(nw string, laddr string) (string, error) {
	ln, err := net.Listen(nw, laddr)
	if err != nil {
		return "", err
	}
	ret := ln.Addr().String()
	reservedListeners[ret] = ln
	return ret, nil
}

// MustReserveListener calls ReserveListener and aborts the test if it fails
func MustReserveListener(t *testing.T, nw string, laddr string) string {
	ret, err := ReserveListener(nw, laddr)
	if err != nil {
		t.Fatalf("failed to reserve listener for %s://%s: %s", err)
	}
	return ret
}

// Listen mimics net.Listen but returns reserved connections whenever possible
func Listen(nw string, laddr string) (net.Listener, error) {
	if ret, ok := reservedListeners[laddr]; ok {
		delete(reservedListeners, laddr)
		return ret, nil
	}
	return net.Listen(nw, laddr)
}
