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

// Package kv contains a generic interface for key-value databases with support
// for batch writes. All operations are safe for concurrent use, atomic and
// synchronously persistent.
package kv

type DB interface {
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	NewBatch() Batch
	Write(Batch) error
	NewIterator(*Range) Iterator

	ErrNotFound() error
}

type Batch interface {
	Reset()
	Put(key, value []byte)
}

type Iterator interface {
	Key() []byte
	Value() []byte
	First() bool
	Last() bool
	Release()
	Error() error
}
