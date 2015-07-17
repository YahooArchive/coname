package icart

import (
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"math/big"
	"testing"
)

func checkOnCurve(t *testing.T, u *big.Int) {
	var x, y big.Int
	ToP384(&x, &y, u)
	if !elliptic.P384().IsOnCurve(&x, &y) {
		t.Errorf("f(%s) is not on curve", u.String())
	}
}

func TestOneOnCurve(t *testing.T) {
	checkOnCurve(t, new(big.Int).SetUint64(1))
}

func TestSomeOnCurve(t *testing.T) {
	checkOnCurve(t, new(big.Int).SetUint64(0xff))
	checkOnCurve(t, new(big.Int).SetUint64((1<<16)|(1<<8)|1))
	checkOnCurve(t, new(big.Int).SetUint64(math.MaxUint64))
}

func TestRandomOnCurve(t *testing.T) {
	for i := 0; i < 128; i++ {
		var b [48]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var u big.Int
		u.SetBytes(b[:])
		checkOnCurve(t, &u)
	}
}

func TestKnown(t *testing.T) {
	for i, tt := range knownTests {
		var u, x, y, xref, yref big.Int
		if _, ok := u.SetString(tt.u, 10); !ok {
			t.Errorf("known test %d: malformed u: %s", i, tt.u)
		}
		if _, ok := xref.SetString(tt.x, 10); !ok {
			t.Errorf("known test %d: malformed x: %s", i, tt.x)
		}
		if _, ok := yref.SetString(tt.y, 10); !ok {
			t.Errorf("known test %d: malformed y: %s", i, tt.y)
		}
		ToP384(&x, &y, &u)
		if x.Cmp(&xref) != 0 || y.Cmp(&yref) != 0 {
			t.Errorf("known test failed: f(%s)", tt.u)
		}
	}
}
