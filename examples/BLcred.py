# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# See: 
#   Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light." 
#   Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. 
#  ACM, 2013.

from hashlib import sha256
from base64 import b64encode

import pytest

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from genzkp import *

class StateHolder(object):
    pass

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

    user_state = StateHolder()
    user_state.params = params
    user_state.attributes = attributes
    user_state.C = C
    user_state.R = R

    return user_state, (C, )

def BL_issuer_keys(params):
    (G, q, g, h, z, hs) = params
    
    x = q.random()
    y = x * g

    issuer_state = StateHolder()
    issuer_state.params = params
    issuer_state.x = x
    issuer_state.y = y

    return issuer_state, (y, )


def BL_issuer_preparation(issuer_state, user_commit):
    (G, q, g, h, z, hs) = issuer_state.params
    (x, y) = (issuer_state.x, issuer_state.y)

    (C, ) = user_commit
    
    # Preparation
    rnd = q.random()
    z1 = C + rnd * g
    z2 = z + (-z1)

    ## Send: (rnd,) to user 
    if rnd % q == 0:
        raise

    issuer_state.rnd = rnd
    issuer_state.z1 = z1
    issuer_state.z2 = z2

    message_to_user = (rnd, )

    return message_to_user

def BL_user_preparation(user_state, msg_from_issuer):
    (G, q, g, h, z, hs) = user_state.params
    (rnd, ) = msg_from_issuer
    C = user_state.C

    z1 = C + rnd * g
    gam = q.random()
    zet = gam * z
    zet1 = gam * z1
    zet2 = zet + (-zet1)
    tau = q.random()
    eta = tau * z

    user_state.z1 = z1
    user_state.gam = gam
    user_state.zet = zet
    user_state.zet1 = zet1
    user_state.zet2 = zet2
    user_state.tau = tau
    user_state.eta = eta

    user_state.rnd = rnd

def BL_issuer_validation(issuer_state):
    (G, q, g, h, z, hs) = issuer_state.params

    u, r1p, r2p, cp = [q.random() for _ in range(4)]
    a = u * g
    a1p = r1p * g + cp * issuer_state.z1
    a2p = r2p * h + cp * issuer_state.z2

    issuer_state.u = u
    issuer_state.r1p = r1p
    issuer_state.r2p = r2p
    issuer_state.cp = cp

    return (a, a1p, a2p)    

def BL_user_validation(user_state, issuer_pub, msg_to_user, message=b''):
    (G, q, g, h, z, hs) = user_state.params
     # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state
    (a, a1p, a2p) = msg_to_user
    (y,) = issuer_pub

    assert G.check_point(a)
    assert G.check_point(a1p)
    assert G.check_point(a2p)

    t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
    alph = a + t1 * g + t2 * y
    alph1 = user_state.gam * a1p + t3 * g + t4 * user_state.zet1
    alph2 = user_state.gam * a2p + t5 * h + t4 * user_state.zet2

    # Make epsilon
    H = [user_state.zet, user_state.zet1, alph, alph1, alph2, user_state.eta]
    Hstr = list(map(EcPt.export, H)) + [message]
    Hhex = b"|".join(map(b64encode, Hstr))
    epsilon = Bn.from_binary(sha256(Hhex).digest()) % q
    
    e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

    user_state.ts = [t1,t2,t3,t4,t5]
    user_state.message = message

    msg_to_issuer = e
    return msg_to_issuer

def BL_issuer_validation_2(issuer_state, msg_from_user):
    (G, q, g, h, z, hs) = issuer_state.params
    # x, y = key_pair
    # (u, r1p, r2p, cp) = issuer_val_private
    e = msg_from_user

    ## Send: (e,) to Issuer
    c = e.mod_sub(issuer_state.cp, q)
    r = issuer_state.u.mod_sub((c * issuer_state.x), q)

    msg_to_user = (c, r, issuer_state.cp, issuer_state.r1p, issuer_state.r2p)
    return msg_to_user

def BL_user_validation2(user_state, msg_from_issuer):
    (G, q, g, h, z, hs) = user_state.params
    (c, r, cp, r1p, r2p) = msg_from_issuer
    (t1,t2,t3,t4,t5), m = user_state.ts, user_state.message

    # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state

    gam = user_state.gam

    ro = r.mod_add(t1,q)
    om = c.mod_add(t2,q)
    ro1p = (gam * r1p + t3) % q
    ro2p = (gam * r2p + t5) % q
    omp = (cp + t4) % q
    mu = (user_state.tau - omp * gam) % q

    signature = (m, user_state.zet, 
                    user_state.zet1, 
                    user_state.zet2, om, omp, ro, ro1p, ro2p, mu)
    
    return signature

def BL_check_signature(params, issuer_pub, signature):
    (G, q, g, h, z, hs) = params
    (y,) = issuer_pub
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

def BL_cred_proof(user_state):
    (G, q, g, h, z, hs) = user_state.params
    gam = user_state.gam

    assert user_state.zet == user_state.gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g

    Cnew = user_state.rnd * gam_g + user_state.R * gam_hs[0]
    for i, attr in enumerate(user_state.attributes):
        Cnew = Cnew + attr * gam_hs[1+i]

    assert Cnew == user_state.zet1

def BL_show_zk_proof(params, num_attrib):
    (G, _, _, _, _, _) = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables

    gam, rnd, R = zk.get(Sec, ["gam", "rnd", "R"])
    attrib = zk.get_array(Sec, "attrib", num_attrib, 0)

    g, z, zet, zet1 = zk.get(ConstGen, ["g", "z", "zet", "zet1"])
    hs = zk.get_array(ConstGen, "hs", num_attrib+1, 0)
    
    zk.add_proof(zet, gam * z)

    gam_g = zk.get(Gen, "gamg")
    zk.add_proof(gam_g, gam * g)

    gam_hs = zk.get_array(Gen, "gamhs", num_attrib+1, 0)

    for gam_hsi, hsi in zip(gam_hs, hs):
        zk.add_proof(gam_hsi, gam * hsi)
    
    Cnew = rnd * gam_g + R * gam_hs[0]
    for i, attr in enumerate(attrib):
        Cnew = Cnew + attr * gam_hs[1+i]

    zk.add_proof(zet1, Cnew)
    return zk

def BL_user_prove_cred(user_state):
    (G, q, g, h, z, hs) = user_state.params
    zk = BL_show_zk_proof(user_state.params, len(user_state.attributes))

    env = ZKEnv(zk)

    # The secrets
    env.gam = user_state.gam
    env.rnd = user_state.rnd
    env.R   = user_state.R
    env.attrib = user_state.attributes

    # Constants
    env.g = g
    env.z = z
    env.zet = user_state.zet
    env.zet1 = user_state.zet1
    env.hs = hs[:len(user_state.attributes) + 1]

    # The stored generators
    env.gamg = user_state.gam * g
    env.gamhs = gam_hs = [user_state.gam * hsi for hsi in hs[:len(user_state.attributes) + 1]]

    ## Extract the proof
    sig = zk.build_proof(env.get())
    if __debug__:
        assert zk.verify_proof(env.get(), sig, strict=False)

    return sig

def BL_verify_cred(params, issuer_pub, num_attributes, signature, sig):
    m = BL_check_signature(params, issuer_pub, signature)    
    assert m != False

    (G, q, g, h, z, hs) = params
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    zk = BL_show_zk_proof(params, num_attributes)

    env = ZKEnv(zk)

    # Constants
    env.g = g
    env.z = z
    env.zet = zet
    env.zet1 = zet1
    env.hs = hs[:num_attributes + 1]

    ## Extract the proof
    res = zk.verify_proof(env.get(), sig)
    assert res

    return m

def test_modular():
    # Establish the global parameters
    params = BL_setup()

    # Generate a key pair (inc. public key) for the issuer
    LT_issuer_state, issuer_pub = BL_issuer_keys(params)
    LT_user_state, user_commit = BL_user_setup(params, [10, 20])

    # Preparation phase
    msg_to_user = BL_issuer_preparation(LT_issuer_state, user_commit)
    BL_user_preparation(LT_user_state, msg_to_user)

    # Validation phase
    msg_to_user = BL_issuer_validation(LT_issuer_state)
    msg_to_issuer = epsilon = BL_user_validation(LT_user_state, issuer_pub, msg_to_user)
    
    msg_to_user = BL_issuer_validation_2(LT_issuer_state, msg_to_issuer)
    signature = BL_user_validation2(LT_user_state, msg_to_user)

    # Build a ZK proof of a valid signature
    sig = BL_user_prove_cred(LT_user_state)

    # Check signature and ZK proof
    m = BL_verify_cred(params, issuer_pub, 2, signature, sig)
    assert m != False


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
