// Package icart implements the Icart function for mapping field elements into
// elliptic curves such that for a hash function h that is one-way , the map
// H(x) = icart(h(x)) is also one-way[0]. Collision-resistance is NOT preserved.
// The icart function is not randomized this implementation IS NOT CONSTANT TIME
// because the math/big is operations are not.
//
// Because the Icart function requires (p % 3) == 2, this package only supports
// elliptic.P384. P224, P256, P521, and Curve25519 have (p % 3) == 1 and are NOT
// compatible with this function.
//
// For an elliptic curve E over a finite field F_p with equation
//     y^2 == x^3 + a*x + b
// and p % 3 == 2, the Icart map f : F_p -> E is defined as follows[1]:
//     v = (3*a - u^4)/(6*u)
//     x = (v^2 - b - u^6/27)^(1/3) + u^2/3
//     y = u*x + v
//     except for f(0), which is defined to be to E.0
// For reference, qube roots modulo p s.t. p % 3 == 2 can be computed as[2]:
//     c^(1/3) = c^((2*p-1)/3)
//
// [0]: https://www.iacr.org/archive/crypto2009/56770300/56770300.pdf section 4
// [1]: https://www.iacr.org/archive/crypto2009/56770300/56770300.pdf section 2
// [2]: https://www.iacr.org/archive/crypto2009/56770300/56770300.pdf section 2
package icart

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

// ToP384 computes (x, y) = f(u) using the icart function f for P-384.
func ToP384(x, y, u *big.Int) {
	initP384Once.Do(initP384)
	icart(elliptic.P384(), x, y, u, &inv3p384, &inv27p384)
}

var initP384Once sync.Once
var inv27p384 big.Int
var inv3p384 big.Int

func initP384() {
	inv3p384.SetUint64(3)
	inv3p384.ModInverse(&inv3p384, elliptic.P384().Params().P)
	inv27p384.SetUint64(27)
	inv27p384.ModInverse(&inv27p384, elliptic.P384().Params().P)
}

// icart computes (x, y) = f(u) using the icart function f for curve. The curve
// MUST satisfy the requirements given in the comment of this package.
func icart(curve elliptic.Curve, x, y, u, inv3, inv27 *big.Int) {
	if u.Sign() == 0 {
		x.SetUint64(0)
		y.SetUint64(0)
	}
	p := curve.Params().P
	var v, u2, t2, t1 big.Int

	u2.Mul(u, u)
	u2.Mod(&u2, p) // u^2
	// t2 is used to construct u^4
	t2.Mul(&u2, &u2)
	t2.Mod(&t2, p) // u^4

	// compute v
	v.SetUint64(9) // 3*a = 3*(-3) for ellptic.Curve
	v.Sub(p, &v)   // 9 < P, cheap Mod
	v.Sub(&v, &t2)
	v.Mod(&v, p) // 3*a - u^4
	// t1 is used to construct the denominator
	t1.SetUint64(6)
	t1.Mul(&t1, u)
	t1.Mod(&t1, p)        // 6*u
	t1.ModInverse(&t1, p) // 1/(6*u)
	v.Mul(&v, &t1)
	v.Mod(&v, p) // (3*a - u^4)/(6*u)

	// compute x
	x.Mul(&v, &v)
	x.Mod(x, p) // v^2
	x.Sub(x, curve.Params().B)
	x.Mod(x, p) // v^2 - b
	// t1 is used to construct u^6/27
	t1.Mul(inv27, &u2)
	t1.Mod(&t1, p)   // u^2/27
	t1.Mul(&t1, &t2) // t2 is still u^4
	t1.Mod(&t1, p)   // u^6/27
	x.Sub(x, &t1)
	x.Mod(x, p) // v^2 - b - u^6/27
	// t1 is used to construct the exponent in the qube root formula
	t1.SetUint64(2)
	t1.Mul(&t1, p) // 2*p
	t2.SetUint64(1)
	t1.Sub(&t1, &t2) // 2*p-1
	t2.SetUint64(3)
	t1.Div(&t1, &t2)  // (2*p - 1)/3
	x.Exp(x, &t1, p)  // (...)^(1/3)
	t2.Mul(&u2, inv3) // u^2/3
	x.Add(x, &t2)
	x.Mod(x, p) // (...)^(1/3) + u^2/3

	y.Mul(u, x)
	y.Mod(y, p) // u*x
	y.Add(y, &v)
	y.Mod(y, p) // u*x + v
}
