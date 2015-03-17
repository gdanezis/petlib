## An implementation of a Parallel Oblivious Unpredictable Function (POUF)
#  Stanislaw Jarecki, Xiaomin Liu: Fast Secure Computation of Set Intersection. 
#  Published in SCN 2010: 418-435

from petlib.ec import EcGroup
import pytest

def POUF_setup(nid=713):
    """Parameters for the group"""
    G = EcGroup(nid)
    g = G.generator()
    o = G.order()
    return (G, g, o)

def POUF_keyGen(params):
    """Generate the secret key k"""
    G, g, o = params
    return o.random()

def POUF_blind(params, messages):
    """Blind the messages input to the POUF"""
    G, g, o = params
    hi = [G.hash_to_point(m) for m in messages]
    ai = [o.random() for _ in messages]
    yi = [a * h for a,h in zip(ai, hi)]
    return ai, yi

def POUF_mac(params, k, yi):
    """ Apply the unpredctable function to the messages """
    return [k * y for y in yi]

def POUF_unblind(params, ai, zi):
    """ Unblind the messages to recover the raw outputs of the POUF """
    G, g, o = params
    xi = [a.mod_inverse(o) * z for a,z in zip(ai, zi)]
    return xi


### ----------- TESTS ---------------

def test_setup():
    params = POUF_setup()
    k = POUF_keyGen(params)
    assert k

def test_blind():
    params = POUF_setup()
    ai, yi = POUF_blind(params, [b"1", b"2"])
    assert len(ai) == 2
    assert len(yi) == 2

def test_mac():
    params = POUF_setup()
    k = POUF_keyGen(params)

    ai, yi = POUF_blind(params, [b"1", b"2"])
    zi = POUF_mac(params, k, yi)
    assert len(zi) == len(ai)

def test_unblind():
    params = POUF_setup()
    G, g, o = params
    k = POUF_keyGen(params)

    ai, yi = POUF_blind(params, [b"1", b"2"])
    zi = POUF_mac(params, k, yi)

    # Make sure unblinding works
    fi = POUF_unblind(params, ai, zi)

    hi = [G.hash_to_point(m) for m in [b"1", b"2"]]
    assert fi == [k * h for h in hi]