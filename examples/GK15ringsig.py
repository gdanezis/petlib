from petlib.ec import EcGroup
from petlib.bn import Bn

from hashlib import sha256

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


def ProveOneOfN(ck, cis, el, r, n = 8):
    assert Com(ck, 0, r) == cis[el]
    (G, g, h, o) = ck

    ## Commit to the bits of the index
    el = Bn(el) # +1
    eli = [Bn(int(el.is_bit_set(i))) for i in range(n)]
    
    ri  = [o.random() for i in range(n)]
    ai  = [o.random() for i in range(n)]
    si  = [o.random() for i in range(n)]
    ti  = [o.random() for i in range(n)]

    Celi = [Com(ck, elix, rix) for elix, rix in zip(eli, ri)]
    Cai = [Com(ck, a, s) for a, s in zip(ai, si)]
    Cbi = [Com(ck, l * a , s) for l, a, s in zip(eli, ai, si)]

    # Compute p_idxi(x)
    p_idx_i = []
    for idx in range(2**n):
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
        cdi_i = Com(ck, 0, roi_i)
        for idx, cidx in enumerate(cis):
            cdi_i += p_idx_i[idx][i] * cidx

        cdi += [ cdi_i ]

    

    #for i in range(0, n):
    #    k = (i + 1) - 1
    #
    #    idxi = [Bn(int(el.is_bit_set(i))) for i in range(n)]

def poly_expand(o, poly, size):
    assert len(poly) <= size
    zero = Bn(0)
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
        pout[i] = (c1 + c2) % o

    return pout

def poly_mul(o, poly1, poly2):
    zero = Bn(0)
    p = [zero]
    for i, c1 in enumerate(poly1):
        p2 = ([zero] * i) + [(c1 * c2) % o for c2 in poly2]
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
    c1 = Com(ck,1, o.random())
    c2 = Com(ck,1, o.random())
    c3 = Com(ck,1, o.random())
    r = o.random()
    cr = Com(ck,0, r)

    cis = [c0, c1, c2, c3, cr]
    proof = ProveOneOfN(ck, cis, 4, r)