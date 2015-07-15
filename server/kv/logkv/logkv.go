// Copyright 2014-2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package logkv

import (
	"log"
	"os"

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

func WithDefaultLogging(db kv.DB) kv.DB {
	return WithLogging(db, log.New(os.Stdout, "", log.LstdFlags))
}

func WithLogging(db kv.DB, l *log.Logger) kv.DB {
	trace := (*traceLogger)(l)
	return tracekv.WithTracing(db, trace.put, trace.batch)
}
