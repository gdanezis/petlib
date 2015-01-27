# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# See: 
#   Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light." 
#   Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. 
#  ACM, 2013.

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from hashlib import sha256

from base64 import b64encode


import pytest


def BL_setup(Gid = 713):
    # Parameters of the BL schemes
    G = EcGroup(713)
    q = G.order()

    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(100)]

    return (G, q, g, h, z, hs)

def BL_user_setup(params, attributes):
    (G, q, g, h, z, hs) = params

    # Inputs from user
    R = q.random()
    C = R * hs[0] # + L1 * hs[1] + L2 * hs[2]

    for (i, attrib_i) in enumerate(attributes):
        C = C + attrib_i * hs[1+i]
    return (C, )

def BL_issuer_keys(params):
    (G, q, g, h, z, hs) = params
    
    x = q.random()
    y = x * g

    return x, y


def BL_issuer_preparation(params, user_commit, issuer_keys):
    (G, q, g, h, z, hs) = params
    (C, ) = user_commit
    (x, y) = issuer_keys

    # Preparation
    rnd = q.random()
    z1 = C + rnd * g
    z2 = z + (-z1)

    ## Send: (rnd,) to user 
    if rnd % q == 0:
        raise

    issuer_state = (x, y, rnd, z1, z2)
    user_state = (rnd, )

    return issuer_state, user_state

def BL_user_preparation(params, user_state, user_commit):
    (G, q, g, h, z, hs) = params
    (rnd,) = user_state
    (C, ) = user_commit

    z1 = C + rnd * g
    gam = q.random()
    zet = gam * z
    zet1 = gam * z1
    zet2 = zet + (-zet1)
    tau = q.random()
    eta = tau * z

    return (z1, gam, zet, zet1, zet2, tau, eta)

def BL_issuer_validation(params, issuer_state):
    (G, q, g, h, z, hs) = params
    (x, y, rnd, z1, z2) = issuer_state


    u, r1p, r2p, cp = [q.random() for _ in range(4)]
    a = u * g
    a1p = r1p * g + cp * z1
    a2p = r2p * h + cp * z2

    return (u, r1p, r2p, cp), (a, a1p, a2p)    

def BL_user_validation(params, issuer_pub, user_val_state, user_private_state, message=b''):
    (G, q, g, h, z, hs) = params
    (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state
    (a, a1p, a2p) = user_val_state
    y = issuer_pub

    assert G.check_point(a)
    assert G.check_point(a1p)
    assert G.check_point(a2p)

    t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
    alph = a + t1 * g + t2 * y
    alph1 = gam * a1p + t3 * g + t4 * zet1
    alph2 = gam * a2p + t5 * h + t4 * zet2

    # Make epsilon
    H = [zet, zet1, alph, alph1, alph2, eta]
    Hstr = list(map(EcPt.export, H)) + [message]
    Hhex = b"|".join(map(b64encode, Hstr))
    epsilon = Bn.from_binary(sha256(Hhex).digest()) % q
    
    e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

    return (t1,t2,t3,t4,t5, message), e

def BL_issuer_validation_2(params, key_pair, issuer_val_private, epsilon):
    (G, q, g, h, z, hs) = params
    x, y = key_pair
    (u, r1p, r2p, cp) = issuer_val_private
    e = epsilon

    ## Send: (e,) to Issuer
    c = e.mod_sub(cp, q)
    r = u.mod_sub((c * x), q)

    return (c, r, cp, r1p, r2p)

def BL_user_validation2(params, user_private_state, user_val_private, from_issuer):
    (G, q, g, h, z, hs) = params
    (c, r, cp, r1p, r2p) = from_issuer
    t1,t2,t3,t4,t5,m = user_val_private
    (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state

    ro = r.mod_add(t1,q)
    om = c.mod_add(t2,q)
    ro1p = (gam * r1p + t3) % q
    ro2p = (gam * r2p + t5) % q
    omp = (cp + t4) % q
    mu = (tau - omp * gam) % q

    signature = (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu)
    return signature

def BL_check_signature(params, issuer_pub, signature):
    (G, q, g, h, z, hs) = params
    y = issuer_pub
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    lhs = (om + omp) % q
    rhs_h = [zet, zet1, 
            ro * g + om * y,
            ro1p * g + omp * zet1,
            ro2p * h + omp * zet2, ## problem
            mu * z + omp * zet]
    
    Hstr = list(map(EcPt.export, rhs_h)) + [m]
    Hhex = b"|".join(map(b64encode, Hstr))
    rhs = Bn.from_binary(sha256(Hhex).digest()) % q
    
    if rhs == lhs:
        return m
    else:
        return False

def test_modular():
    # Establish the global parameters
    params = BL_setup()

    # Generate a key pair (inc. public key) for the issuer
    key_pair = BL_issuer_keys(params)
    _, issuer_pub = key_pair

    # Preparation phase
    user_commit = BL_user_setup(params, [10, 20])
    issuer_private_state, user_state = BL_issuer_preparation(params, user_commit, key_pair)
    user_private_state = BL_user_preparation(params, user_state, user_commit)

    # Validation phase
    issuer_val_private, user_val_state = BL_issuer_validation(params, issuer_private_state)
    user_val_private, epsilon = BL_user_validation(params, issuer_pub, user_val_state, user_private_state)
    to_user = BL_issuer_validation_2(params, key_pair, issuer_val_private, epsilon)
    signature = BL_user_validation2(params, user_private_state, user_val_private, to_user)

    # Check signature
    assert BL_check_signature(params, issuer_pub, signature) != False

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

    # Check the (future) ZK proof
    assert zet == gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g
    assert rnd * gam_g + R * gam_hs[0] + L1 * gam_hs[1] + L2 * gam_hs[2] == zet1

    
    print(rhs == lhs)
