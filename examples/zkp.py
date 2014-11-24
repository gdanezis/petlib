## An example of the simple Schnor sigma protocol
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
    H.update(state)
    return H.digest()

def prove(G, h, g, x, m=""):
    """Schnor proof of the statement ZK(x ; h = g^x)"""
    assert x * g == h
    o = G.order()
    w = o.random()
    W = w * g

    state = ['schnor', G.nid(), g, h, m, W]
    hash_c = challenge(state)
    c = Bn.from_binary(hash_c) % o
    r = (w - c * x) % o
    return (c, r)

def verify(G, h, g, proof, m=""):
    """Verify the statement ZK(x ; h = g^x)"""
    c, r = proof
    W = (r * g + c * h)

    state = ['schnor', G.nid(), g, h, m, W]
    hash_c = challenge(state)
    c2 = Bn.from_binary(hash_c) % o
    return c == c2


if __name__ == "__main__":
    G = EcGroup(409)
    g = G.generator()
    o = G.order()
    x = o.random()
    h = x * g

    ## Use it as a Zk proof
    proof = prove(G, h, g, x)
    assert verify(G, h, g, proof)
    assert not verify(G, g, h, proof)

    ## Use it as a signature scheme
    proofm = prove(G, h, g, x, m = "Hello World!")
    assert verify(G, h, g, proofm, m = "Hello World!")
    assert not verify(G, h, g, proofm, m = "Other String")
