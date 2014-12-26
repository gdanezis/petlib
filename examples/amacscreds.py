## An implementation of the credential scheme based on an algebraic
## MAC proposed by Chase, Meiklejohn and Zaverucha in Algebraic MACs and Keyed-Veriffcation 
## Anonymous Credentials", at ACM CCS 2014. The credentials scheme
## is based on the GGM based aMAC. (see section 4.2, pages 8-9)

from amacs import *
from genzkp import *

def lnames(name, n):
    assert type(name) == str
    return [name+"%i" % i for i in range(1, n+1)]

def cred_setup():
    params = setup_ggm()
    return params

def cred_CredKeyge(params, n):
    _, g, h, o = params
    sk, iparams = keyGen_ggm(params, n)
    x0_bar = o.random()
    Cx0 = sk[0] * g + x0_bar * h
    return (Cx0, iparams), (sk, x0_bar)

def cred_issue_proof(params, n):
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables
    u, up, g, h, Cx0 = zk.get(ConstGen, ["u", "up", "g", "h", "Cx0"])
    x0, x0_bar =  zk.get(Sec, ["x0", "x0_bar"])

    xi_names = lnames("x", n) 
    mi_names = lnames("m", n) 
    Xi_names = lnames("X", n) 

    xis = zk.get(Sec, xi_names)
    mis = zk.get(Pub, mi_names)
    Xis = zk.get(ConstGen, Xi_names)

    ## Proof of correct MAC
    Prod = x0 * u
    for (xi, mi) in zip(xis, mis):
        Prod = Prod + xi*(mi * u) 
    zk.add_proof(up, Prod)

    ## Proof of knowing the secret of MAC
    zk.add_proof(Cx0, x0 * g + x0_bar * h)

    ## Proof of correct Xi's
    for (xi, Xi) in zip(xis, Xis):
        zk.add_proof(Xi, xi * h)        

    return zk

def cred_issue(params, publics, secrets, messages):

    # Parse variables
    G, g, h, _ = params
    sk, x0_bar = secrets
    Cx0, iparams = publics
    (u, uprime) = mac_ggm(params, sk, messages)

    # Build the proof and associate real variables
    zk = cred_issue_proof(params, len(messages))

    env = {
        "g": g, "h": h,
        "u": u, "up": uprime,
        "x0": sk[0], "x0_bar": x0_bar,
        "Cx0": Cx0
    }

    n = len(messages)
    xi_names = lnames("x", n)
    mi_names = lnames("m", n) 
    Xi_names = lnames("X", n)

    ivars = zip(xi_names, sk[1:]) \
            + zip(mi_names, messages) \
            + zip(Xi_names, iparams)

    env.update(dict(ivars))

    ## Extract the proof
    sig = zk.build_proof(env)

    ## Return the credential (MAC) and proof of correctness
    return (u, uprime), sig

def cred_issue_check(params, publics, mac, sig, messages):
    
    # Parse public variables
    G, g, h, _ = params
    Cx0, iparams = publics
    (u, uprime) = mac

    # Build the proof and assign public variables
    zk = cred_issue_proof(params, len(messages))

    env = {
        "g": g, "h": h,
        "u": u, "up": uprime,
        "Cx0": Cx0
    }

    n = len(messages)
    mi_names = lnames("m", n) 
    Xi_names = lnames("X", n) 

    ivars = zip(mi_names, messages) \
            + zip(Xi_names, iparams)

    env.update(dict(ivars))

    # Return the result of the verification
    return zk.verify_proof(env, sig)

def cred_show_proof(params, n):
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables
    u, g, h = zk.get(ConstGen, ["u", "g", "h"])
    
    zi_names = lnames("z", n)
    mi_names = lnames("m", n)
    Xi_names = lnames("X", n)
    Cmi_names = lnames("Cm", n)

    V = zk.get(ConstGen, "V")
    minus_one = zk.get(ConstPub, "-1")
    r = zk.get(Sec, "r")

    zis = zk.get(Sec, zi_names)
    mis = zk.get(Sec, mi_names)
    Xis = zk.get(ConstGen, Xi_names)
    Cmis = zk.get(ConstGen, Cmi_names)

    Vp = r * (minus_one * g)
    for zi, Xi in zip(zis, Xis):
        Vp = Vp + (zi * Xi)
    zk.add_proof(V, Vp)

    for (Cmi, mi, zi) in zip(Cmis, mis, zis):
        zk.add_proof(Cmi, mi*u + zi*h)

    return zk

def cred_show(params, publics, mac, sig, messages):
    ## Parse and re-randomize
    G, g, h, o = params
    Cx0, iparams = publics
    u, uprime = rerandomize_sig_ggm(params, mac)

    n = len(messages)
    
    ## Blinding variables for the proof
    r = o.random()
    zis = [o.random() for _ in range(n)]

    Cup = uprime + r * g
    Cmis = [mi * u + zi * h for (mi, zi) in zip(messages, zis)]

    cred = (u, Cmis, Cup)

    V = r * ( (-1) * g)
    for zi, Xi in zip(zis, iparams):
        V = V + zi * Xi

    # Define the proof, and instanciate it with variables
    zk = cred_show_proof(params, n)

    env = {
        "u": u, "g": g, "h": h,
        "V": V, "r": r, "-1": -Bn(1)
    }

    zi_names = lnames("z", n)
    mi_names = lnames("m", n)
    Xi_names = lnames("X", n)
    Cmi_names = lnames("Cm", n)

    env.update(zip(zi_names, zis))    
    env.update(zip(mi_names, messages))    
    env.update(zip(Xi_names, iparams))    
    env.update(zip(Cmi_names, Cmis))    

    sig = zk.build_proof(env)
    ## Just a sanity check
    assert zk.verify_proof(env, sig)

    return cred, sig

def cred_show_check(params, publics, secrets, creds, sig):

    # Parse the inputs
    G, g, h, _ = params
    sk, _ = secrets
    Cx0, iparams = publics
    (u, Cmis, Cup) = creds

    n = len(iparams)

    ## Recompute a V
    V = sk[0] * u + (- Cup)
    for xi, Cmi in zip(sk[1:], Cmis):
        V = V + xi * Cmi

    # Define the proof, and instanciate it with variables
    zk = cred_show_proof(params, n)

    env = {
        "u": u, "g": g, "h": h,
        "V": V, "-1": -Bn(1)
    }

    Xi_names = lnames("X", n)
    Cmi_names = lnames("Cm", n)

    env.update(zip(Xi_names, iparams))    
    env.update(zip(Cmi_names, Cmis))    

    # Return the result of the verification
    return zk.verify_proof(env, sig)


def test_creds():
    ## Setup from credential issuer.
    params = cred_setup()
    ipub, isec = cred_CredKeyge(params, 2)

    ## Credential issuing and checking
    mac, sig = cred_issue(params, ipub, isec, [10, 20])
    assert cred_issue_check(params, ipub, mac, sig, [10, 20])

    ## The show protocol
    (creds, sig) = cred_show(params, ipub, mac, sig, [10, 20])
    assert cred_show_check(params, ipub, isec, creds, sig)