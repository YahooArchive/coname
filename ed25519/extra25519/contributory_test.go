// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package extra25519

import (
	"crypto/rand"
	"testing"

	"github.com/yahoo/coname/ed25519/edwards25519"
)

func TestLE1IsIdentity(t *testing.T) {
	var le1 edwards25519.ExtendedGroupElement
	le1.FromBytes(&[32]byte{1})
	for i := 0; i < 1000; i++ {
		var x [32]byte
		rand.Reader.Read(x[:])
		x[31] &= 127
		x[31] |= 64
		x[0] &= 248
		var X, Y edwards25519.ExtendedGroupElement
		edwards25519.GeScalarMultBase(&X, &x)

		edwards25519.GeAdd(&Y, &X, &le1)

		var XB, YB [32]byte
		X.ToBytes(&XB)
		Y.ToBytes(&YB)
		if XB != YB {
			t.Fatalf("+=LE1 is not identity on %x=g^%x", X, x)
		}
	}
}

var order = decimalLE("57896044618658097711785492504343953926856930875039260848015607506283634007912")

func TestMultOrderIdentity(t *testing.T) {
	for i := 0; i < 1000; i++ {
		var x [32]byte
		rand.Reader.Read(x[:])
		x[31] &= 127
		x[31] |= 64
		x[0] &= 248
		var X edwards25519.ExtendedGroupElement
		edwards25519.GeScalarMultBase(&X, &x)

		edwards25519.GeScalarMult(&X, order, &X)
		var outB [32]byte
		X.ToBytes(&outB)
		if outB != [32]byte{1} {
			t.Fatalf("(g^%x)^%x != 0 (got %x)", x, order, outB)
		}
	}
}

func TestCheckSubgroupImplsAgreeNegative(t *testing.T) {
	for i, pB := range badPoints {
		var p edwards25519.ExtendedGroupElement
		p.FromBytes(pB)
		if checkContributoryRef(&p) != false {
			t.Errorf("subgroup check passed bad point %d (%x)", i, p)
		}
		if checkContributoryCurve25519(&p) != false {
			t.Errorf("blacklist check passed bad point %d (%x)", i, p)
		}
	}
}

func TestCheckContributoryRefPassesRandom(t *testing.T) {
	for i := 0; i < 1000; i++ {
		var x [32]byte
		rand.Reader.Read(x[:])
		x[31] &= 127
		var X edwards25519.ExtendedGroupElement
		edwards25519.GeScalarMultBase(&X, &x)

		if checkContributoryRef(&X) == false {
			t.Fatalf("subgroup check rejected random point %d: %x = g^%x", i, X, x)
		}
	}
}

func TestCheckContributoryCurve25519PassesRandom(t *testing.T) {
	for i := 0; i < 1000; i++ {
		var x [32]byte
		rand.Reader.Read(x[:])
		x[31] &= 127
		var X edwards25519.ExtendedGroupElement
		edwards25519.GeScalarMultBase(&X, &x)

		if checkContributoryCurve25519(&X) == false {
			t.Fatalf("subgroup check rejected random point %x = g^%x", X, x)
		}
	}
}
