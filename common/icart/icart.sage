proof.arithmetic(False) # turn off primality checking

# P384
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
F = GF(p)
A = p - 3
B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
q = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
g = E(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)
E = EllipticCurve([F(A), F(B)])
E.set_order(q)

def icart(u):
	u = F(u)
	v = (3*A - u^4)//(6*u)
	x = (v^2 - B - u^6/27)^((2*p-1)//3) + u^2/3
	y = u*x + v
	return E(x, y) # raises expection if not on curve

inputs = [1, 7, 13, 1<<7, 1<<8, 1<<64, 1<<64-1, p-1, p+1]
tts = [(u, icart(u)) for u in inputs]

knownHeader = """package icart

var knownTests = []struct {
	u, x, y string
}{
"""
knownFooter="}"

print(knownHeader)
for u, p in tts:
	p.normalize_coordinates()
	print('{"%s", "%s", "%s"},' % (int(u), int(p._coords[0]), int(p._coords[1])))
print(knownFooter)
