package iterator_test

import (
	"testing"

	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb/testutil"
)

func TestIterator(t *testing.T) {
	testutil.RunSuite(t, "Iterator Suite")
}
