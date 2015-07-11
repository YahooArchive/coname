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

// Package tracekv implements a tracing wrapper for kv.DB
package tracekv

import (
	"fmt"

	"github.com/yahoo/coname/server/kv"
)

type tracekv struct {
	kv.DB
	tracePut   func(Put)
	traceBatch func([]Put)
}

func WithTracing(db kv.DB, tracePut func(Put), traceBatch func([]Put)) kv.DB {
	return tracekv{db, tracePut, traceBatch}
}

func mapPut(f func(Put)) func([]Put) {
	return func(ps []Put) {
		for _, p := range ps {
			f(p)
		}
	}
}

func WithSimpleTracing(db kv.DB, tracePut func(Put)) kv.DB {
	return WithTracing(db, tracePut, mapPut(tracePut))
}

func (db tracekv) Get(key []byte) ([]byte, error) {
	return db.DB.Get(key)
}

func (db tracekv) Put(key, value []byte) error {
	err := db.DB.Put(key, value)
	db.tracePut(Put{key, value})
	return err
}

func (db tracekv) NewBatch() kv.Batch {
	return &traceBatch{nil, db.DB.NewBatch()}
}

func (db tracekv) Write(b kv.Batch) error {
	wb, ok := b.(*traceBatch)
	if !ok {
		return fmt.Errorf("tracekv.Write: expected *tracekv.traceBatch, got %T", b)
	}
	err := db.DB.Write(wb.b)
	db.traceBatch(wb.operations)
	return err
}

func (db tracekv) NewIterator(rg *kv.Range) kv.Iterator {
	return db.DB.NewIterator(rg)
}

func (db tracekv) ErrNotFound() error {
	return db.DB.ErrNotFound()
}

type traceBatch struct {
	operations []Put
	b          kv.Batch
}
type Put struct {
	Key, Value []byte
}

func (lb *traceBatch) Reset() {
	lb.operations = nil
	lb.b.Reset()
}

func (lb *traceBatch) Put(key, value []byte) {
	lb.operations = append(lb.operations, Put{key, value})
}
