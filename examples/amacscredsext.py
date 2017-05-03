from amacscreds import *


def _internal_ckeck(keypair, u, EncE, secrets, all_attribs):
    """ Check the invariant that the ciphertexts are the encrypted attributes """

    ## First do decryption
    priv, pub = keypair
    (a, b) = EncE
    Cred = b - (priv * a)

    sk, _ = secrets
    v = Hx(sk, all_attribs)
    assert Cred == v * u


def _check_enc(params, keypair, EGenc, attrib):
    G, g, h, o = params
    priv, pub = keypair
    for (a, b, atr) in zip(EGenc[0], EGenc[1], attrib):
        assert (b - (priv * a)) == (atr * g)


def cred_cert_proof(params, n):
    G, _, _, _ = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables
    g, h, u = zk.get(ConstGen, ["g", "h", "u"])
    Cmis = zk.get_array(ConstGen, "Cmi", n)
    Cx0, VplusCup = zk.get(ConstGen, ["Cx0","VplusCup"])
    x0, x0_bar =  zk.get(Sec, ["x0", "x0_bar"])
    xis = zk.get_array(Sec, "xi", n)
    Xis = zk.get_array(ConstGen, "Xi", n)

    ## Proof of knowing the secret of MAC
    zk.add_proof(Cx0, x0 * g + x0_bar * h)

    ## Proof of correct Xi's
    for (xi, Xi) in zip(xis, Xis):
        zk.add_proof(Xi, xi * h)        

    # Define the relations to prove
    Vp = x0 * u
    for xi, Cmi in zip(xis, Cmis):
        Vp = Vp + (xi * Cmi)
    zk.add_proof(VplusCup, Vp)

    return zk


def cred_show_check_cert(params, publics, secrets, creds, sig, cred_show_proof=cred_show_proof, xenv={}):

    # Parse the inputs
    G, g, h, _ = params
    sk, x0_bar = secrets
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

    if xenv:
        xenv(env)


    Correct = zk.verify_proof(env.get(), sig)

    if not Correct:
        return False, None

    # Define the cert proof
    zkcert = cred_cert_proof(params, n)
    env = ZKEnv(zkcert)
    env.VplusCup = V + Cup
    env.u = u
    env.g, env.h = g, h
    env.Cmi = Cmis
    env.Cx0 = Cx0
    env.x0 = sk[0]
    env.x0_bar = x0_bar
    env.xi = sk[1:]
    env.Xi = iparams


    sig = zkcert.build_proof(env.get()) 
    if __debug__:
        assert zkcert.verify_proof(env.get(), sig, strict=False)


    # Return the result of the verification
    return Correct, (V, sig)

def public_check_cert(params, publics, cert, creds, sig, cred_show_proof=cred_show_proof, xenv={}):
    # Parse the inputs
    G, g, h, _ = params
    Cx0, iparams = publics
    (u, Cmis, Cup) = creds

    n = len(iparams)

    ## Recompute a V
    V, sig2 = cert

    # Define the proof, and instanciate it with variables
    zk = cred_show_proof(params, n)

    env = ZKEnv(zk)
    env.u = u
    env.g, env.h = g, h
    env.V = V
    env.minus1 = -Bn(1)
    env.Xi = iparams
    env.Cmi = Cmis

    if xenv:
        xenv(env)

    Correct = zk.verify_proof(env.get(), sig)
    if not Correct:
        return False

    # Define the cert proof
    zkcert = cred_cert_proof(params, n)
    env = ZKEnv(zkcert)

    # zk.VplusCup = ConstGen
    env.VplusCup = V + Cup
    env.u = u
    env.g, env.h = g, h
    env.Cmi = Cmis
    env.Cx0 = Cx0
    env.Xi = iparams

    Correct = zkcert.verify_proof(env.get(), sig2, strict=True)
    if not Correct:
        return False

    return True

def test_secret_creds_ext():
    ## Setup from credential issuer.
    params = cred_setup()

    ## Attriutes we want to encode
    public_attr = [30, 40]
    private_attr = [10, 20]
    n = len(public_attr) + len(private_attr)

    ipub, isec = cred_CredKeyge(params, n)

    ## User generates keys and encrypts some secret attributes
    #  the secret attributes are [10, 20]
    keypair = cred_UserKeyge(params)
    pub, EGenc, sig = cred_secret_issue_user(params, keypair, private_attr)
    
    if __debug__:
        _check_enc(params, keypair, EGenc, private_attr)

    ## The issuer checks the secret attributes and encrypts a amac
    #  It also includes some public attributes, namely [30, 40].
    assert cred_secret_issue_user_check(params, pub, EGenc, sig)
    u, EncE, sig = cred_secret_issue(params, pub, EGenc, ipub, isec, public_attr)
    
    if __debug__:
        _internal_ckeck(keypair, u, EncE, isec, public_attr + private_attr)

    ## The user decrypts the amac
    mac = cred_secret_issue_user_decrypt(params, keypair, u, EncE, ipub, public_attr, EGenc, sig)
    
    ## The show protocol using the decrypted amac
    #  The proof just proves knowledge of the attributes, but any other 
    #  ZK statement is also possible by augmenting the proof.
    (creds, sig) = cred_show(params, ipub, mac, sig, public_attr + private_attr)
    res, cert = cred_show_check_cert(params, ipub, isec, creds, sig)
    assert res

    ## Check the public certificate that is returned by the verification step
    public_check_cert(params, ipub, cert, creds, sig)
