package table

import (
	"testing"

	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb/testutil"
)

func TestTable(t *testing.T) {
	testutil.RunSuite(t, "Table Suite")
}
