# This is a reference implementation of the algebraic 
# Message Authentication Code construction by Chase, Meiklejohn 
# and Zaverucha (see "Algebraic MACs and Keyed-Veriffcation 
# Anonymous Credentials", at ACM CCS 2014). 

from petlib.ec import EcGroup
import pytest

def setup_ggm(nid = 713):
    """Generates the parameters for an EC group nid"""
    G = EcGroup(nid)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen_ggm(params, n):
    """Secret key setup and parameter setup for issuer"""
    (_, _, h, o) = params    
    sk = [o.random() for _ in range(n+1)]
    iparams = [s * h for s in sk[1:]]
    return sk, iparams

def Hx(sk, messages):
    """A helper function Hx"""
    assert len(messages) == len(sk) - 1
    total = sk[0]
    for xi, mi in zip(sk[1:], messages):
        total = total + (xi * mi)
    return total

def mac_ggm(params, sk, messages):
    """Compute the mac on messages"""
    _, g, _, o = params
    u = o.random() * g
    uprime = Hx(sk, messages) * u
    return (u, uprime)

def verify_ggm(params, sk, messages, sig):
    """Verify the mac on messages"""
    u, uprime = sig
    G, _, _, _ = params

    if u == G.infinite():
        raise Exception("Invalid MAC: u point at infinity.")

    if uprime == Hx(sk, messages) * u:
        return True
    return False

def rerandomize_sig_ggm(params, sig):
    _, _, _, o = params
    u, up = sig
    r = o.random()
    return r * u, r * up

def test_mac():
    """Test basic GGM amac"""
    params = setup_ggm()
    sk, iparams = keyGen_ggm(params, 2)
    sig = mac_ggm(params, sk, [10, 20])
    assert verify_ggm(params, sk, [10, 20], sig)
    assert not verify_ggm(params, sk, [10, 30], sig)

    sig2 = rerandomize_sig_ggm(params, sig)
    assert verify_ggm(params, sk, [10, 20], sig2)
