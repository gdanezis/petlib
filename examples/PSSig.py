""" An implementation of the Pointcheval-Sanders Short Randomizable Signatures 
scheme, to demononstrate the capabilities of the petlib.bp module. For full details
of the scheme see:

David Pointcheval, Olivier Sanders: Short Randomizable Signatures. CT-RSA 2016: 111-126

"""

from petlib.bp import BpGroup

def setup():
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	e, o = G.pair, G.order()
	return (G, o, g1, g2, e)

def keygen(params):
	(G, o, g1, g2, e) = params
	(x, y) = o.random(), o.random()
	sk = (x, y)
	pk = (g2, x*g2, y*g2)
	return (sk, pk)

def sign(params, sk, m):
	(G, o, g1, g2, e) = params
	(x, y) = sk
	h = (o.random()) * g1
	sig = (x+y*m) * h
	return (h, sig)

def verify(params, pk, m, sig):
	(G, o, g1, g2, e) = params
	(g, X, Y) = pk
	sig1 , sig2 = sig
	return not sig1.isinf() and e(sig1, X + m * Y) == e(sig2, g)

def randomize(params, sig):
	(G, o, g1, g2, e) = params
	sig1 , sig2 = sig
	t = o.random()
	return ( t*sig1 , t*sig2 )

# ---------- TESTS -------------

def test_setup():
	setup()

def test_keygen():
	params = setup()
	sk, pk = keygen(params)

def test_sign():
	params = setup()
	sk, pk = keygen(params)

	from petlib.bn import Bn
	from hashlib import sha256

	m = Bn.from_binary(sha256("Hello World!").digest())
	sign(params, sk,  m)

def test_verify():
	params = setup()
	sk, pk = keygen(params)

	from petlib.bn import Bn
	from hashlib import sha256

	m = Bn.from_binary(sha256("Hello World!").digest())
	signature = sign(params, sk,  m)

	assert verify(params, pk, m, signature)

	m2 = Bn.from_binary(sha256("Other Hello World!").digest())
	assert not verify(params, pk, m2, signature)

def test_randomize():
	params = setup()
	sk, pk = keygen(params)

	from petlib.bn import Bn
	from hashlib import sha256

	m = Bn.from_binary(sha256("Hello World!").digest())
	signature = sign(params, sk,  m)

	signature = randomize(params, signature)

	assert verify(params, pk, m, signature)

	m2 = Bn.from_binary(sha256("Other Hello World!").digest())
	assert not verify(params, pk, m2, signature)

