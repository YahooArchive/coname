package server

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/andres-erbsen/tlstestutil"
)

func TestKeyserverStartStop(t *testing.T) {
	dir, err := ioutil.TempDir("", "keyserver")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ca, caPool, caKey := tlstestutil.CA(t, nil)
	cert := tlstestutil.Cert(t, ca, caKey, "127.0.0.1", nil)
	cfg := &Config{
		LeveldbDir: dir,

		UpdateAddr:   "localhost:0",
		LookupAddr:   "localhost:0",
		VerifierAddr: "localhost:0",
		UpdateTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		LookupTLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		VerifierTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caPool, ClientAuth: tls.RequireAndVerifyClientCert},

		MinEpochInterval:   0,
		MaxEpochInterval:   100 * time.Millisecond,
		RetryEpochInterval: 10 * time.Millisecond,
	}
	ks, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ks.Start()
	ks.Stop()
	if testing.Verbose() {
		time.Sleep(time.Millisecond)
		n := runtime.NumGoroutine()
		stackBuf := make([]byte, 1014)
		var l int
		for l = runtime.Stack(stackBuf, true); l == len(stackBuf) && l < 128*1024; {
			stackBuf = append(stackBuf, stackBuf...)
		}
		t.Logf("%d goroutines in existance after Stop:\n%s", n, stackBuf[:l])
	}
}
