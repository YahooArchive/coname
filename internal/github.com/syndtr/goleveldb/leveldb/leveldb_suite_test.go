package leveldb

import (
	"testing"

	"github.com/yahoo/coname/internal/github.com/syndtr/goleveldb/leveldb/testutil"
)

func TestLevelDB(t *testing.T) {
	testutil.RunSuite(t, "LevelDB Suite")
}
