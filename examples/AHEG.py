## An implementation of an additivelly homomorphic 
## ECC El-Gamal scheme, used in Privex.

from petlib.ec import EcGroup
import pytest

def params_gen(nid=713):
    """Generates the AHEG for an EC group nid"""
    G = EcGroup(nid)
    g = G.generator()
    o = G.order()
    return (G, g, o)

def key_gen(params):
    """Generates a fresh key pair"""
    _, g, o = params
    priv = o.random()
    pub = priv * g
    return (pub, priv)

def enc(params, pub, counter):
    """Encrypts the values of a small counter"""
    assert -2**8 < counter < 2**8
    G, g, o = params

    k = o.random()
    a = k * g
    b = k * pub + counter * g
    return (a, b)

def add(c1, c2):
    """Add two encrypted counters"""
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + a2, b1 + b2)

def mul(c1, val):
    """Multiplies an encrypted counter by a public value"""
    a1, b1 = c1
    return (val*a1, val*b1)

def randomize(params, pub, c1):
    """Rerandomize an encrypted counter"""
    zero = enc(params, pub, 0)
    return add(c1, zero)

def make_table(params):
    """Make a decryption table"""
    _, g, o = params
    table = {}
    for i in range(-1000, 1000):
        table[i * g] = i
    return table

def dec(params, table, priv, c1):
    """Decrypt an encrypted counter"""
    _, g, o = params
    a, b = c1
    plain = b + (-priv * a)
    return table[plain] 

def test_AHEG():
    params = params_gen()
    (pub, priv) = key_gen(params)
    table = make_table(params)

    # Check encryption and decryption
    one = enc(params, pub, 1)
    assert dec(params, table, priv, one) == 1

    # Check addition
    tmp = add(one, one)
    two = randomize(params, pub, tmp)
    assert dec(params, table, priv, two) == 2

    # Check multiplication
    tmp1 = mul(two, 2)
    four = randomize(params, pub, tmp1)
    assert dec(params, table, priv, four) == 4
