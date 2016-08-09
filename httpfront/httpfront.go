package httpfront

import (
	//"errors"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/maditya/protobuf/jsonpb"
	"github.com/yahoo/coname/proto"
	"golang.org/x/net/context"
)

// HTTPFront implements a dumb http proxy for the keyserver grpc interface
type HTTPFront struct {
	Lookup      func(context.Context, *proto.LookupRequest) (*proto.LookupProof, error)
	Update      func(context.Context, *proto.UpdateRequest) (*proto.LookupProof, error)
	SAMLRequest func() (string, error)
	OIDCRequest func(string, string) (string, error)
	InRotation  func() bool

	// this is needed due to https://github.com/golang/go/issues/14374
	TLSConfig *tls.Config

	ln net.Listener
	sr http.Server

	connStateMu sync.Mutex
	connState   map[net.Conn]http.ConnState

	stopOnce sync.Once
	stop     chan struct{}
	waitStop sync.WaitGroup // server + all open connections
}

func (h *HTTPFront) Start(ln net.Listener) {
	h.stop = make(chan struct{})
	h.connState = make(map[net.Conn]http.ConnState)
	h.sr = http.Server{
		Addr:           ln.Addr().String(),
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 4096,
		ConnState:      h.updateConnState,
		TLSConfig:      h.TLSConfig,
	}
	h.ln = ln
	h.waitStop.Add(1)
	go h.run()
}

func (h *HTTPFront) run() {
	defer h.waitStop.Done()
	h.sr.Serve(h.ln)
}

func (h *HTTPFront) Stop() {
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

func (h *HTTPFront) updateConnState(c net.Conn, s http.ConnState) {
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

func (h *HTTPFront) doLookup(b io.Reader, ctx context.Context) (*proto.LookupProof, error) {
	lr := &proto.LookupRequest{}
	err := jsonpb.Unmarshal(b, lr)
	if err != nil {
		return nil, err
	}

	pf, err := h.Lookup(ctx, lr)
	if err != nil {
		return nil, err
	}
	return pf, nil

}

func (h *HTTPFront) doUpdate(b io.Reader, ctx context.Context) (*proto.LookupProof, error) {
	ur := &proto.UpdateRequest{}
	err := jsonpb.Unmarshal(b, ur)
	if err != nil {
		return nil, err
	}

	pf, err := h.Update(ctx, ur)
	if err != nil {
		return nil, err
	}
	return pf, nil

}

func (h *HTTPFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	// service healthcheck
	if (method == "HEAD" || method == "GET") && (path == "/status" || path == "/lb") {
		if !h.InRotation() {
			http.Error(w, `server out of rotation`, http.StatusNotFound)
			return
		}
		if method == "GET" {
			w.Write([]byte("OK"))
		}
		return
	}

	if method == "GET" && path == "/saml" {
		url, err := h.SAMLRequest()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
	if method == "GET" && path == "/oidc" {
		u, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, `error parsing query string`, http.StatusBadRequest)
			return
		}
		d := u.Get("domain")
		if d == "" {
			http.Error(w, `domain not found`, http.StatusBadRequest)
			return
		}

		url, err := h.OIDCRequest(d, "https://"+r.Host+"/oidcsso")
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
	}

	if method != "POST" || (path != "/lookup" && path != "/update") {
		http.Error(w, `this server only supports queries of the POST /lookup or POST /update`, http.StatusNotFound)
		return
	}
	pf := &proto.LookupProof{}
	var err error
	ctx := context.Background()
	if path == "/lookup" {
		pf, err = h.doLookup(r.Body, ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if path == "/update" {
		pf, err = h.doUpdate(r.Body, ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	// preserve the original field name
	marshaler := jsonpb.Marshaler{OrigName: true}
	err = marshaler.Marshal(w, pf)
	if err != nil {
		http.Error(w, `Internal server error`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	return
}
