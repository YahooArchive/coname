package hkpfront

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/yahoo/coname"
	"github.com/yahoo/coname/proto"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/net/context"
)

// HKPFront implements a unverified GnuPG-compatible HKP frontend for the
// verified keyserver.
type HKPFront struct {
	Lookup func(context.Context, *proto.LookupRequest) (*proto.LookupProof, error)
	Clk    clock.Clock

	InsecureSkipVerify bool
	// Config must be set and valid if InsecureSkipVerify is not set
	Config *proto.Config

	ln net.Listener
	sr http.Server

	connStateMu sync.Mutex
	connState   map[net.Conn]http.ConnState

	stopOnce sync.Once
	stop     chan struct{}
	waitStop sync.WaitGroup // server + all open connections
}

func (h *HKPFront) Start(ln net.Listener) {
	h.stop = make(chan struct{})
	h.connState = make(map[net.Conn]http.ConnState)
	h.sr = http.Server{
		Addr:           ln.Addr().String(),
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 4096,
		ConnState:      h.updateConnState,
	}
	h.ln = ln
	h.waitStop.Add(1)
	go h.run()
}

func (h *HKPFront) run() {
	defer h.waitStop.Done()
	h.sr.Serve(h.ln)
}

func (h *HKPFront) Stop() {
	h.stopOnce.Do(func() {
		close(h.stop)
		h.sr.SetKeepAlivesEnabled(false)
		h.ln.Close()

		h.connStateMu.Lock()
		for c, s := range h.connState {
			if s == http.StateIdle {
				c.Close()
			}
		}
		h.connStateMu.Unlock()

		h.waitStop.Wait()
	})
}

func (h *HKPFront) updateConnState(c net.Conn, s http.ConnState) {
	h.connStateMu.Lock()
	defer h.connStateMu.Unlock()
	h.connState[c] = s
	switch s {
	case http.StateNew:
		h.waitStop.Add(1)
	case http.StateIdle:
		select {
		case <-h.stop:
			c.Close()
		default:
		}
	case http.StateClosed, http.StateHijacked:
		h.waitStop.Done()
		delete(h.connState, c)
	}
}

func (h *HKPFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method != "GET" || r.URL.Path != "/pks/lookup" || len(q["op"]) != 1 || q["op"][0] != "get" || len(q["search"]) != 1 {
		http.Error(w, `this server only supports queries of the form "/pks/lookup?op=get&search=<EMAIL>"`, 501)
		return
	}
	user := q["search"][0]
	ctx := context.Background()

	var requiredSignatures *proto.QuorumExpr
	if !h.InsecureSkipVerify {
		realm, err := coname.GetRealmByUser(h.Config, user)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		switch realm.VerificationPolicy.PolicyType.(type) {
		case *proto.AuthorizationPolicy_Quorum:
			requiredSignatures = realm.VerificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum).Quorum
		default:
		}
	}

	pf, err := h.Lookup(ctx, &proto.LookupRequest{UserId: user, QuorumRequirement: requiredSignatures})
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	if !h.InsecureSkipVerify {
		coname.VerifyLookup(h.Config, user, pf, h.Clk.Now())
	}

	if pf.Profile == nil || pf.Profile.Keys == nil {
		http.Error(w, `No results found: No keys found: unknown email`, 404)
		return
	}

	pgpKey, present := pf.Profile.Keys["pgp"]
	if !present {
		http.Error(w, `No results found: No keys found: the email is known to the keyserver, but the profile does not include an OpenPGP key`, 404)
		return
	}

	if _, mr := q["mr"]; mr {
		w.Header().Set("Content-Type", "application/pgp-keys")
	}
	aw, err := armor.Encode(w, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, err = aw.Write(pgpKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := aw.Close(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
