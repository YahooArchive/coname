package server

import (
	"crypto/tls"
	"net"
	"sync"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/replication"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	UpdateAddr, LookupAddr, VerifierAddr string
	UpdateTLS, LookupTLS, VerifierTLS    *tls.Config // TODO: make this struct serializable. tls.Config is not

	log replication.ReplicatedLog // TODO: cluster init information?
}

type Keyserver struct {
	updateServer, lookupServer, verifierServer *grpc.Server
	updateListen, lookupListen, verifierListen net.Listener

	log replication.ReplicatedLog

	close    chan struct{}
	waitStop sync.WaitGroup
}

func Bind(cfg *Config) (ks *Keyserver, err error) {
	ks = &Keyserver{log: cfg.log, close: make(chan struct{})}
	if cfg.UpdateAddr != "" {
		ks.updateServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.UpdateTLS)))
		proto.RegisterE2EKSUpdateServer(ks.updateServer, ks)
		ks.updateListen, err = net.Listen("tcp", cfg.UpdateAddr)
		if err != nil {
			return nil, err
		}
	}
	if cfg.LookupAddr != "" {
		ks.lookupServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.LookupTLS)))
		proto.RegisterE2EKSLookupServer(ks.lookupServer, ks)
		ks.lookupListen, err = net.Listen("tcp", cfg.LookupAddr)
		if err != nil {
			ks.updateListen.Close()
			return nil, err
		}
	}
	if cfg.VerifierAddr != "" {
		ks.verifierServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.VerifierTLS)))
		ks.verifierListen, err = net.Listen("tcp", cfg.VerifierAddr)
		if err != nil {
			ks.updateListen.Close()
			ks.lookupListen.Close()
			return nil, err
		}
	}
	return ks, nil
}

func (ks *Keyserver) Start() {
	ks.log.Start(0) // NOTE: when persistent state is implemented, bump this index on every batch sync
	if ks.updateServer != nil {
		go ks.updateServer.Serve(ks.updateListen)
	}
	if ks.lookupServer != nil {
		go ks.lookupServer.Serve(ks.lookupListen)
	}
	if ks.verifierServer != nil {
		go ks.verifierServer.Serve(ks.verifierListen)
	}
	ks.waitStop.Add(1)
	go func() { ks.waitClose(); ks.waitStop.Done() }()
}

func (ks *Keyserver) Stop() {
	close(ks.close)
	ks.waitStop.Wait()
	ks.log.Close()
}

func (ks *Keyserver) waitClose() {
	<-ks.close
	if ks.updateServer != nil {
		ks.updateServer.Stop()
	}
	if ks.lookupServer != nil {
		ks.lookupServer.Stop()
	}
	if ks.verifierServer != nil {
		ks.verifierServer.Stop()
	}
}
