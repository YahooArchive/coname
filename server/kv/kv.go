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
