package logkv

import (
	"log"

	"github.com/yahoo/coname/server/kv"
	"github.com/yahoo/coname/server/kv/tracekv"
)

type traceLogger log.Logger

func (l *traceLogger) put(p tracekv.Put) {
	(*log.Logger)(l).Printf("put %q := %q", p.Key, p.Value)
}

func (l *traceLogger) batch(ps []tracekv.Put) {
	(*log.Logger)(l).Printf("batch {")
	for _, p := range ps {
		(*log.Logger)(l).Printf("\t%q := %q", p.Key, p.Value)
	}
	(*log.Logger)(l).Printf("}")
}

func WithLogging(db kv.DB, l *log.Logger) kv.DB {
	trace := (*traceLogger)(l)
	return tracekv.WithTracing(db, trace.put, trace.batch)
}
