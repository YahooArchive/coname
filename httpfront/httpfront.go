package httpfront

import (
	//"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/andres-erbsen/protobuf/jsonpb"
	"github.com/yahoo/coname/proto"
	"golang.org/x/net/context"
)

// HTTPFront implements a dumb http proxy for the keyserver grpc interface
type HTTPFront struct {
	Lookup     func(context.Context, *proto.LookupRequest) (*proto.LookupProof, error)
	Update     func(context.Context, *proto.UpdateRequest) (*proto.LookupProof, error)
	InRotation func() bool

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

func (h *HTTPFront) doUpdate(b io.Reader, ctx context.Context, userid string) (*proto.LookupProof, error) {
	ur := &proto.UpdateRequest{}
	err := jsonpb.Unmarshal(b, ur)
	if err != nil {
		return nil, err
	}

	// TODO: uncomment the check below if we have any user auth at http layer,
	// else remove this altogether
	//if useridReq, useridAuth := ur.LookupParameters.UserId, userid; useridReq != useridAuth {
	//	return nil, errors.New("userid mismatch in request body and auth, " + useridReq + " vs " + useridAuth)
	//}

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

	userid, err := auth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if method != "POST" || (path != "/lookup" && path != "/update") {
		http.Error(w, `this server only supports queries of the POST /lookup or POST /update`, http.StatusNotFound)
		return
	}
	pf := &proto.LookupProof{}
	ctx := context.Background()
	if path == "/lookup" {
		pf, err = h.doLookup(r.Body, ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if path == "/update" {
		pf, err = h.doUpdate(r.Body, ctx, userid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	marshaler := jsonpb.Marshaler{}
	err = marshaler.Marshal(w, pf)
	if err != nil {
		http.Error(w, `Internal server error`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	return
}
