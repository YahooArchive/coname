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

// Package leveldbkv implements the kv interface using leveldb
package leveldbkv

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/yahoo/coname/server/kv"
)

type leveldbkv leveldb.DB

func Wrap(db *leveldb.DB) kv.DB {
	return (*leveldbkv)(db)
}

func (db *leveldbkv) Get(key []byte) ([]byte, error) {
	return (*leveldb.DB)(db).Get(key, nil)
}

func (db *leveldbkv) Put(key, value []byte) error {
	return (*leveldb.DB)(db).Put(key, value, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) NewBatch() kv.Batch {
	return new(leveldb.Batch)
}

func (db *leveldbkv) Write(b kv.Batch) error {
	wb, ok := b.(*leveldb.Batch)
	if !ok {
		return fmt.Errorf("leveldbkv.Write: expected *leveldb.Batch, got %T", b)
	}
	return (*leveldb.DB)(db).Write(wb, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) NewIterator(rg *kv.Range) kv.Iterator {
	return (*leveldb.DB)(db).NewIterator(&util.Range{rg.Start, rg.Limit}, nil)
}

func (db *leveldbkv) ErrNotFound() error {
	return leveldb.ErrNotFound
}
