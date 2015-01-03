# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# See: 
#	Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light." 
#   Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. 
#  ACM, 2013.

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from hashlib import sha256

from base64 import b64encode


import pytest

def test_protocol():
	# Parameters of the BL schemes
	G = EcGroup(713)
	q = G.order()

	g = G.hash_to_point(b"g")
	h = G.hash_to_point(b"h")
	z = G.hash_to_point(b"z")
	hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(100)]

	# Inputs from user
	R = q.random()
	L1 = 10
	L2 = 20
	C = R * hs[0] + L1 * hs[1] + L2 * hs[2]
	m = b"Hello World!"

	# Inputs from the Issuer
	# TODO: check ZK on C
	x = q.random()
	y = x * g

	# Preparation
	rnd = q.random()
	z1 = C + rnd * g
	z2 = z + (-z1)

	## Send: (rnd,) to user 
	if rnd % q == 0:
		raise

	z1 = C + rnd * g
	gam = q.random()
	zet = gam * z
	zet1 = gam * z1
	zet2 = zet + (-zet1)
	tau = q.random()
	eta = tau * z

	# Validation: Issuer
	u, r1p, r2p, cp = [q.random() for _ in range(4)]
	a = u * g
	a1p = r1p * g + cp * z1
	a2p = r2p * h + cp * z2

	## Send(a, ap = (a1p, a2p))
	# User side

	assert G.check_point(a)
	assert G.check_point(a1p)
	assert G.check_point(a2p)

	t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
	alph = a + t1 * g + t2 * y
	alph1 = gam * a1p + t3 * g + t4 * zet1
	alph2 = gam * a2p + t5 * h + t4 * zet2

	# Make epsilon
	H = [zet, zet1, alph, alph1, alph2, eta]
	Hstr = list(map(EcPt.export, H)) + [m]
	Hhex = b"|".join(map(b64encode, Hstr))
	epsilon = Bn.from_binary(sha256(Hhex).digest()) % q
	
	e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

	## Send: (e,) to Issuer
	c = e.mod_sub(cp, q)
	r = u.mod_sub((c * x), q)

	## Send: (c,r, cp, rp = (r1p, r2p)) to User
	ro = r.mod_add(t1,q)
	om = c.mod_add(t2,q)
	ro1p = (gam * r1p + t3) % q
	ro2p = (gam * r2p + t5) % q
	omp = (cp + t4) % q
	mu = (tau - omp * gam) % q

	signature = (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p)

	# Check verification equation
	lhs = (om + omp) % q
	rhs_h = [zet, zet1, 
			ro * g + om * y,
			ro1p * g + omp * zet1,
			ro2p * h + omp * zet2, ## problem
			mu * z + omp * zet]
	
	Hstr = list(map(EcPt.export, rhs_h)) + [m]
	Hhex = b"|".join(map(b64encode, Hstr))
	rhs = Bn.from_binary(sha256(Hhex).digest()) % q
	
	print(rhs == lhs)
