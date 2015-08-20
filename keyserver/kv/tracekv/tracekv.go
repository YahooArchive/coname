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

	"github.com/yahoo/coname/keyserver/kv"
)

type tracekv struct {
	kv.DB
	traceUpdate func(Update)
	traceBatch  func([]Update)
}

// WithTracing returns a kv.DB that calls traceUpdate on every Put or Delete
// and traceBatch on every Write.
func WithTracing(db kv.DB, traceUpdate func(Update), traceBatch func([]Update)) kv.DB {
	return tracekv{db, traceUpdate, traceBatch}
}

func mapUpdate(f func(Update)) func([]Update) {
	return func(ps []Update) {
		for _, p := range ps {
			f(p)
		}
	}
}

// WithSimpleTracing returns a kv.DB that calls traceUpdate on every Put
// (regardless of whether it is issued by itself or during a Batch Write).
func WithSimpleTracing(db kv.DB, traceUpdate func(Update)) kv.DB {
	return WithTracing(db, traceUpdate, mapUpdate(traceUpdate))
}

func (db tracekv) Get(key []byte) ([]byte, error) {
	return db.DB.Get(key)
}

func (db tracekv) Put(key, value []byte) error {
	err := db.DB.Put(key, value)
	db.traceUpdate(Update{key, value, false})
	return err
}

func (db tracekv) Delete(key []byte) error {
	err := db.DB.Delete(key)
	db.traceUpdate(Update{key, nil, true})
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
	operations []Update
	b          kv.Batch
}

// Update represents a single change to a kv.DB.
type Update struct {
	Key, Value []byte
	IsDeletion bool
}

func (lb *traceBatch) Reset() {
	lb.operations = nil
	lb.b.Reset()
}

func (lb *traceBatch) Put(key, value []byte) {
	lb.operations = append(lb.operations, Update{key, value, false})
	lb.b.Put(key, value)
}

func (lb *traceBatch) Delete(key []byte) {
	lb.operations = append(lb.operations, Update{key, nil, true})
	lb.b.Delete(key)
}
