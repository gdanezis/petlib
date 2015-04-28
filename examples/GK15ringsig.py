from petlib.ec import EcGroup
from petlib.bn import Bn

from hashlib import sha256
import math

## ######################################################
## An implementation of the ring signature scheme in
## 
##    Jens Groth and Markulf Kohlweiss. "One-out-of-Many Proofs: 
##    Or How to Leak a Secret and Spend a Coin"
##    Cryptology ePrint Archive: Report 2014/764
##
## https://eprint.iacr.org/2014/764
## ######################################################

def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = list(map(str, elem))
    elem_len = list(map(lambda x: "%s||%s" % (len(x) , x), elem_str))
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return Bn.from_binary(H.digest())

def setup():
    """ Generates parameters for Commitments """
    G = EcGroup()
    g = G.hash_to_point(b'g')
    h = G.hash_to_point(b'h')
    o = G.order()
    return (G, g, h, o)

def Com(ck, m, k):
    """ Pedersen Commitment. """
    (G, g, h, o) = ck
    return m * g + k * h    


def ProveZeroOne(ck, c, m, r):
    """ Simple proof that a Commitment c = Com(m,r) is either 0 or 1 """
    assert Com(ck, m, r) == c
    (G, g, h, o) = ck
    a, s, t = o.random(), o.random(), o.random()
    ca = Com(ck, a, s)
    cb = Com(ck, a*m, t)
    x = challenge([g, h, ca, cb]) % o
    f = (x * m + a) % o
    za = (r * x + s) % o
    zb = (r * (x - f) + t) % o
    return (x, f, za, zb)

def VerifyZeroOne(ck, c, proof):
    """ Verify that a Commitment c = Com(m,r) is either 0 or 1 """
    (G, g, h, o) = ck
    (x, f, za, zb) = proof

    assert 0 < x < o
    assert 0 < f < o
    assert 0 < za < o
    assert 0 < zb < o

    ca = Com(ck,f,za) - x * c
    cb = Com(ck, 0, zb) - (x-f) * c
    xp = challenge([g, h, ca, cb]) % o
    return xp == x


def ProveOneOfN(ck, cis, el, r, message = ""):
    """ NIZK Proof that Com(0; r) is within Cis. 
        The fact that it is the el'th commitmtnet is not revealed. 
        + Ring signature on "message". """
    n = int(math.ceil(math.log(len(cis)) / math.log(2)))
    assert Com(ck, 0, r) == cis[el]
    (G, g, h, o) = ck

    ## Commit to the bits of the index
    el = Bn(el)
    eli = [Bn(int(el.is_bit_set(i))) for i in range(n)]
    
    ri  = [o.random() for i in range(n)]
    ai  = [o.random() for i in range(n)]
    si  = [o.random() for i in range(n)]
    ti  = [o.random() for i in range(n)]

    Celi = [Com(ck, elix, rix) for elix, rix in zip(eli, ri)]
    Cai = [Com(ck, a, s) for a, s in zip(ai, si)]
    Cbi = [Com(ck, l * a , s) for l, a, s in zip(eli, ai, ti)]

    # Compute p_idxi(x)
    p_idx_i = []
    for idx in range(len(cis)):
        idx = Bn(idx)
        idxi = [Bn(int(idx.is_bit_set(i))) for i in range(n)]

        p = [Bn(1)]
        for j, idxi_j in enumerate(idxi):
            if idxi_j == 0:
                p = poly_mul(o, p, [ -ai[j] , - eli[j] + 1] )
            else:
                p = poly_mul(o, p, [ ai[j] , eli[j] ])

        p_idx_i += [p]
        
    # Compute all Cdi's
    roi = []
    cdi = []
    for i in range(n):
        roi_i = o.random()
        roi += [ roi_i ]
        # cdi_i = Com(ck, 0, roi_i)

        wis = []

        for idx, cidx in enumerate(cis):
            wis += [ p_idx_i[idx][i] ]
            # cdi_i += p_idx_i[idx][i] * cidx

        # assert G.wsum(wis, cis) + Com(ck, 0, roi_i) == cdi_i
        cdi_i = G.wsum(wis, cis) + Com(ck, 0, roi_i)

        cdi += [ cdi_i ]

    ## The challenge
    x = challenge(list(ck) + cis + Celi + Cai + Cbi + cdi + [ message ])

    ## The responses
    fi = [(elj * x + aj) % o for elj, aj in zip(eli, ai)]
    zai = [(rj * x + sj) % o for rj, sj in zip(ri, si)]
    zbi = [(rj * (x - fj) + tj) % o for rj, fj, tj in zip(ri, fi, ti)]

    zd = r * pow(x, n, o) % o
    for k in range(n):
        zd = (zd - roi[k] * pow(x, k, o)) % o

    proof = (Celi, Cai, Cbi, cdi, fi, zai, zbi, zd)

    return proof

def VerifyOneOfN(ck, cis, proof, message = ""):
    """ Verify the ring signature on message """

    n = int(math.ceil(math.log(len(cis)) / math.log(2)))
    (G, g, h, o) = ck

    (Celi, Cai, Cbi, cdi, fi, zai, zbi, zd) = proof

    ## Check all parts of the proof are in the right groups
    assert 0 <= zd < o
    for k in range(n):
        assert 0 <= fi[k] < o
        assert 0 <= zai[k] < o
        assert 0 <= zbi[k] < o
        
        assert G.check_point(Celi[k])
        assert G.check_point(Cai[k])
        assert G.check_point(Cbi[k])
        assert G.check_point(cdi[k])

    # Recompute the challenge
    x = challenge(list(ck) + cis + Celi + Cai + Cbi + cdi + [ message ])


    ret = True

    for i in range(n):
        ret &= x * Celi[i] + Cai[i] == Com(ck, fi[i], zai[i])
        ret &= (x - fi[i]) * Celi[i] + Cbi[i] == Com(ck, Bn(0), zbi[i])

    # acc = G.infinite()

    bases = []
    expons = []

    for idx, ci in enumerate(cis):
        idx = Bn(idx)
        idxi = [Bn(int(idx.is_bit_set(i))) for i in range(n)]

        acc_exp = Bn(1)
        for k, ij in enumerate(idxi):
            if ij == 0:
                acc_exp = acc_exp.mod_mul(x - fi[k], o)
            else:
                acc_exp = acc_exp.mod_mul(fi[k], o)

        bases += [ ci ]
        expons += [ acc_exp ]

        # acc = acc + acc_exp * ci

    for k in range(n):
        expi = (- pow(x,k,o))
        # acc = acc + expi * cdi[k]
        bases += [ cdi[k] ]
        expons += [ expi ]

    # assert G.wsum(expons, bases) == acc
    acc = G.wsum(expons, bases)

    ret &= acc == Com(ck, 0, zd)

    return ret


## ######################################
## Naive polynomial arithmetic
zero = Bn(0)

def poly_expand(o, poly, size):
    global zero

    assert len(poly) <= size
    # zero = Bn(0)
    new_poly = [zero for _ in range(size)]
    for i in range(len(poly)):
        new_poly[i] = poly[i]
    return new_poly

def poly_add(o, poly1, poly2):
    size = max(len(poly1), len(poly2))
    p1 = poly_expand(o, poly1, size)
    p2 = poly_expand(o, poly2, size)

    pout = poly_expand(o, [], size)
    for i, (c1, c2) in enumerate(zip(p1, p2)):
        pout[i] = c1.mod_add( c2,  o)

    return pout

def poly_mul(o, poly1, poly2):
    global zero
    p = [ zero ]
    for i, c1 in enumerate(poly1):
        p2 = ([ zero ] * i) + [(c1.mod_mul(c2, o)) for c2 in poly2]
        p = poly_add(o, p2, p)
    return p

###################################################
# ----------------  TESTS ----------------------- #
###################################################

import pytest

def test_poly_expand():
    ck = setup()
    (G, g, h, o) = ck
    p1 = [Bn(1), Bn(2)]
    p2 = poly_expand(o, p1, 10)
    assert len(p2) == 10
    assert p2[:2] == p1

def test_poly_add():
    ck = setup()
    (G, g, h, o) = ck
    p1 = [Bn(1), Bn(2)]
    p2 = poly_add(o, p1, p1)
    assert len(p2) == len(p1)
    assert p2 == [2, 4]

def test_poly_mul():
    ck = setup()
    (G, g, h, o) = ck
    p1 = [Bn(1), Bn(2)]
    p2 = poly_mul(o, p1, p1)
    assert p2 == [1, 4, 4]

def test_setup():
    ck = setup()

def test_proof():
    ck = setup()
    (G, g, h, o) = ck
    m, r = 1, o.random()
    c = Com(ck, m, r)
    ProveZeroOne(ck, c, m, r)

@pytest.mark.parametrize("input,expected", [
    (1, True),
    (0, True),
    (2, False),
])
def test_verify(input,expected):
    ck = setup()
    (G, g, h, o) = ck
    m, r = input, o.random()
    c = Com(ck, m, r)

    proof = ProveZeroOne(ck, c, m, r)
    assert VerifyZeroOne(ck, c, proof) == expected

def test_prove_n():
    ck = setup()
    (G, g, h, o) = ck
    c0 = Com(ck, 1, o.random())
    c1 = Com(ck, 1, o.random())
    c2 = Com(ck, 1, o.random())
    c3 = Com(ck, 1, o.random())
    r = o.random()
    cr = Com(ck,0, r)

    cis = [c0, c1, c2, c3, cr]
    proof = ProveOneOfN(ck, cis, 4, r, message="Hello World!")
    ret = VerifyOneOfN(ck, cis, proof, message="Hello World!")
    assert ret

def notest_timing(upper=101):
    ck = setup()
    (G, g, h, o) = ck
    c0 = Com(ck, 1, o.random())
    
    r = o.random()
    cr = Com(ck,0, r)

    import time

     
    repeats = 10

    all_sizes = range(10, upper, 10)
    prove_time = []
    verify_time = []
    for size in all_sizes:
        cis = [c0] * (size + 1) + [cr]   

        t0 = time.clock() 
        for _ in range(repeats):
            proof = ProveOneOfN(ck, cis, len(cis)-1, r, message="Hello World!")
        t1 = time.clock()

        dt = (t1-t0) / repeats
        prove_time += [ dt ]
        print( "Proof time: %s - %2.4f" % (size, dt) )

        t0 = time.clock() 
        for _ in range(repeats):
            ret = VerifyOneOfN(ck, cis, proof, message="Hello World!")
            assert ret
        t1 = time.clock()

        dt = (t1-t0) / repeats
        verify_time += [ dt ]
        print( "Verify time: %s - %2.4f" % (size, dt) )

    return all_sizes, prove_time, verify_time


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description='Test and time the Tor median statistics.')
    parser.add_argument('--time', action='store_true', help='Run timing tests')
    parser.add_argument('--lprof', action='store_true', help='Run the line profiler')
    parser.add_argument('--cprof', action='store_true', help='Run the c profiler')
    parser.add_argument('--plot', action='store_true', help='Upload time plot to plotly')


    args = parser.parse_args()

    if args.time:
        notest_timing(31)


    if args.cprof:
        import cProfile
        cProfile.run("notest_timing(51)", sort="tottime")
        

    if args.lprof:
        from line_profiler import LineProfiler

        profile = LineProfiler(VerifyOneOfN, ProveOneOfN, Bn.__init__, Bn.__del__)
        profile.run("notest_timing(31)")
        profile.print_stats()

    
    if args.plot:

        all_sizes, prove_time, verify_time = notest_timing()

        import plotly.plotly as py
        from plotly.graph_objs import *

        trace0 = Scatter(
            x=all_sizes,
            y=prove_time,
            name='Proving',
        )
        trace1 = Scatter(
            x=all_sizes,
            y=verify_time,
            name='Verification',
        )
        data = Data([trace0, trace1])
        
        layout = Layout(
            title='Timing for GK15 Proof and Verification using petlib',
            xaxis=XAxis(
                title='Size of ring (no. commits)',
                showgrid=False,
                zeroline=False
            ),
            yaxis=YAxis(
                title='time (sec)',
                showline=False
            )
        )
        fig = Figure(data=data, layout=layout)

        unique_url = py.plot(fig, filename = 'GK15-petlib-timing')