## An implementation of the credential scheme based on an algebraic
## MAC proposed by Chase, Meiklejohn and Zaverucha in Algebraic MACs and Keyed-Verification 
## Anonymous Credentials", at ACM CCS 2014. The credentials scheme
## is based on the GGM based aMAC. (see section 4.2, pages 8-9)

from amacs import *
from genzkp import *

def cred_setup():
    """ Generates the parameters of the algebraic MAC scheme"""
    params = setup_ggm()
    return params

def cred_CredKeyge(params, n):
    """ Generates keys and parameters for the credential issuer """
    _, g, h, o = params
    sk, iparams = keyGen_ggm(params, n)
    x0_bar = o.random()
    Cx0 = sk[0] * g + x0_bar * h
    return (Cx0, iparams), (sk, x0_bar)

def cred_UserKeyge(params):
    """ Generates keys and parameters for credential user """
    G, g, h, o = params
    priv = o.random()
    pub = priv * g     # This is just an EC El-Gamal key
    return (priv, pub)

def secret_proof(params, n):
    """ Builds a proof of correct El-Gamal encryption for a number of secret attributes. """
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    # Some constants and secrets
    pub, g, h = zk.get(ConstGen, ["pub", "g", "h"])
    priv = zk.get(Sec, "priv")

    ## The El-Gamal ciphertexts and secrets
    ris = zk.get_array(Sec, "ri", n)
    attrs = zk.get_array(Sec, "attri", n)
    sKis = zk.get_array(ConstGen, "sKi", n)
    Cis = zk.get_array(ConstGen, "Ci", n)

    # The proof obligations
    zk.add_proof(pub, priv * g)
    for (Ci, sKi, ri, attr) in zip(Cis, sKis, ris, attrs):
        zk.add_proof(sKi, ri * g)
        zk.add_proof(Ci, ri * pub + attr * g)

    return zk


def cred_secret_issue_user(params, keypair, attrib):
    """ Encodes a number of secret attributes to be issued. """
    
    # We simply encrypt all parameters and make a proof we know
    # the decryption.
    G, g, h, o = params
    priv, pub = keypair

    ris = []
    sKis = []
    Cis = []

    for i, attr in enumerate(attrib):
        ri = o.random()
        ris += [ri]
        sKis += [ri * g]
        Cis += [ri * pub + attr * g]

    zk = secret_proof(params, len(attrib))

    ## Run the proof
    env = ZKEnv(zk) 
    env.g, env.h = g, h
    env.pub = pub
    env.priv = priv

    env.ri = ris
    env.attri = attrib
    env.sKi = sKis
    env.Ci = Cis

    ## Extract the proof
    sig = zk.build_proof(env.get())

    return (pub, (sKis, Cis), sig)

def _check_enc(params, keypair, EGenc, attrib):
    G, g, h, o = params
    priv, pub = keypair
    for (a, b, atr) in zip(EGenc[0], EGenc[1], attrib):
        assert (b - (priv * a)) == (atr * g)


def cred_secret_issue_user_check(params, pub, EGenc, sig):
    """ Check the encrypted attributes of a user are well formed.
    """
    G, g, h, o = params
    (sKis, Cis) = EGenc

    ## First check the inputs (EG ciphertexts) are well formed.
    assert len(sKis) == len(Cis)
    zk = secret_proof(params, len(Cis))

    ## Run the proof
    env = ZKEnv(zk) 
    env.g, env.h = g, h
    env.pub = pub

    env.sKi = sKis
    env.Ci = Cis

    ## Extract the proof
    if not zk.verify_proof(env.get(), sig):
        raise Exception("Proof of knowledge of plaintexts failed.")

def cred_secret_issue(params, pub, EGenc, publics, secrets, messages):
    """ Encode a mixture of secret (EGenc) and public (messages) attributes"""

    # Parse variables
    G, g, h, o = params
    sk, x0_bar = secrets
    Cx0, iparams = publics
    (sKis, Cis) = EGenc

    assert len(sKis) == len(Cis)
    assert len(iparams) == len(messages) + len(Cis)

    # Get a blinding b
    b = o.random()
    u = b * g

    bx0_bar = b.mod_mul(x0_bar, o)
    bsk = []
    for xi in sk:
        bsk += [b.mod_mul(xi, o)]

    bCx0 = b * Cx0
    bXi = []
    for Xi in iparams:
        bXi += [b * Xi]

    bsk0 = bsk[0]
    open_bsk = bsk[1:len(messages)+1]
    sec_bsk  = bsk[len(messages)+1:len(messages)+1+len(Cis)]
    assert [bsk0] + open_bsk + sec_bsk == bsk

    # First build a proto-credential in clear using all public attribs
    Cred = bsk0 * g
    for bxi, msg in zip(open_bsk, messages):
        Cred = Cred + (bxi.mod_mul(msg, o)) * g

    r_prime = o.random()
    EG_a = r_prime * g
    EG_b = r_prime * pub + Cred

    for (eg_ai, eg_bi, bxi) in zip(sKis, Cis, sec_bsk):
        EG_a = EG_a + bxi * eg_ai
        EG_b = EG_b + bxi * eg_bi

    return u, (EG_a, EG_b)

def _internal_ckeck(keypair, u, EncE, secrets, all_attribs):
    """ Check the invariant that the ciphertexts are the encrypted attributes """

    ## First do decryption
    priv, pub = keypair
    (a, b) = EncE
    Cred = b + (- (priv * a))

    sk, _ = secrets
    v = Hx(sk, all_attribs)
    assert Cred == v * u

def cred_secret_issue_user_decrypt(keypair, u, EncE):
    priv, pub = keypair
    (a, b) = EncE
    uprime = b + (- (priv * a))

    return (u, uprime)

def cred_issue_proof(params, n):
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables
    u, up, g, h, Cx0 = zk.get(ConstGen, ["u", "up", "g", "h", "Cx0"])
    x0, x0_bar =  zk.get(Sec, ["x0", "x0_bar"])

    xis = zk.get_array(Sec, "xi", n)
    mis = zk.get_array(Pub, "mi", n)
    Xis = zk.get_array(ConstGen, "Xi", n)

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
    n = len(messages)
    zk = cred_issue_proof(params, n)

    env = ZKEnv(zk)

    env.g, env.h = g, h 
    env.u, env.up = u, uprime
    env.x0 = sk[0]
    env.x0_bar = x0_bar
    env.Cx0 = Cx0

    env.xi = sk[1:]
    env.mi = messages
    env.Xi = iparams

    ## Extract the proof
    sig = zk.build_proof(env.get())

    ## Return the credential (MAC) and proof of correctness
    return (u, uprime), sig

def cred_issue_check(params, publics, mac, sig, messages):
    
    # Parse public variables
    G, g, h, _ = params
    Cx0, iparams = publics
    (u, uprime) = mac

    # Build the proof and assign public variables
    n = len(messages)
    zk = cred_issue_proof(params, n)

    env = ZKEnv(zk)
    env.g, env.h = g, h 
    env.u, env.up = u, uprime
    env.Cx0 = Cx0

    env.mi = messages
    env.Xi = iparams

    # Return the result of the verification
    return zk.verify_proof(env.get(), sig)

def cred_show_proof(params, n):
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables
    u, g, h = zk.get(ConstGen, ["u", "g", "h"])
    V = zk.get(ConstGen, "V")
    minus_one = zk.get(ConstPub, "minus1")
    r = zk.get(Sec, "r")

    zis = zk.get_array(Sec, "zi", n)
    mis = zk.get_array(Sec, "mi", n)
    Xis = zk.get_array(ConstGen, "Xi", n)
    Cmis = zk.get_array(ConstGen, "Cmi", n)

    # Define the relations to prove
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

    ## WARNING: this step not in paper description of protocol
    #           Checked correctness with Sarah Meiklejohn.
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

    env = ZKEnv(zk)
    env.u = u
    env.g, env.h = g, h
    env.V = V
    env.r = r
    env.minus1 = -Bn(1)

    env.zi = zis
    env.mi = messages
    env.Xi = iparams
    env.Cmi = Cmis

    sig = zk.build_proof(env.get())
    ## Just a sanity check
    assert zk.verify_proof(env.get(), sig)

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

    env = ZKEnv(zk)
    env.u = u
    env.g, env.h = g, h
    env.V = V
    env.minus1 = -Bn(1)

    env.Xi = iparams
    env.Cmi = Cmis

    # Return the result of the verification
    return zk.verify_proof(env.get(), sig)


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


def test_secret_creds():
    ## Setup from credential issuer.
    params = cred_setup()
    ipub, isec = cred_CredKeyge(params, 4)

    ## User generates keys and encrypts some secret attributes
    #  the secret attributes are [10, 20]
    keypair = cred_UserKeyge(params)
    pub, EGenc, sig = cred_secret_issue_user(params, keypair, [10, 20])
    _check_enc(params, keypair, EGenc, [10, 20])

    ## The issuer checks the secret attributes and encrypts a amac
    #  It also includes some public attributes, namely [30, 40].
    cred_secret_issue_user_check(params, pub, EGenc, sig)
    u, EncE = cred_secret_issue(params, pub, EGenc, ipub, isec, [30, 40])
    _internal_ckeck(keypair, u, EncE, isec, [30, 40] + [10, 20])

    ## The user decrypts the amac
    mac = cred_secret_issue_user_decrypt(keypair, u, EncE)

    ## The show protocol using the decrypted amac
    #  The proof just proves knowledge of the attributes, but any other 
    #  ZK statement is also possible by augmenting the proof.
    (creds, sig) = cred_show(params, ipub, mac, sig, [30, 40, 10, 20])
    assert cred_show_check(params, ipub, isec, creds, sig)

