## An example of the simple Schnorr sigma protocol
## to prove that one knows x, such that h = g^x for 
## a public generator h and g.

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from hashlib import sha256

def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return H.digest()
    

def setup():
    G = EcGroup(713)
    g = G.generator()
    o = G.order()
    return G, g, o

def prove(params, h, g, x, m=""):
    """Schnorr proof of the statement ZK(x ; h = g^x)"""
    assert x * g == h
    G, _, o = params
    w = o.random()
    W = w * g

    state = ['schnorr', G.nid(), g, h, m, W]
    hash_c = challenge(state)
    c = Bn.from_binary(hash_c) % o
    r = (w - c * x) % o
    return (c, r)

def verify(params, h, g, proof, m=""):
    """Verify the statement ZK(x ; h = g^x)"""
    G, _, o = params
    c, r = proof
    W = (r * g + c * h)

    state = ['schnorr', G.nid(), g, h, m, W]
    hash_c = challenge(state)
    c2 = Bn.from_binary(hash_c) % o
    return c == c2


def test_zkp():
    params = setup()
    G, g, o = params
    x = o.random()
    h = x * g

    ## Use it as a Zk proof
    proof = prove(params, h, g, x)
    assert verify(params, h, g, proof)
    assert not verify(params, g, h, proof)

    ## Use it as a signature scheme
    proofm = prove(params, h, g, x, m = "Hello World!")
    assert verify(params, h, g, proofm, m = "Hello World!")
    assert not verify(params, h, g, proofm, m = "Other String")
