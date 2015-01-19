from .bindings import _C
from .ec import EcGroup, _check
from .bn import Bn

def do_ecdsa_sign(G, priv, data):
    """A quick function to ECDSA sign a hash.

    Args:
        G (EcGroup): the group in which math is done.
        priv (Bn): the secret key
        data (str): the string to sign

    Returns:
        Bn, Bn: The (r, s) signature

    Example:
        How to use ``do_ecdsa_sign`` and ``do_ecdsa_verify`` to sign and verify a string:

        >>> from hashlib import sha1
        >>> # Generate a signature / verification key pair.
        >>> G = EcGroup()
        >>> sig_key = G.order().random()
        >>> ver_key = sig_key * G.generator()
        >>> # Hash the (potentially long) message into a short digest.
        >>> digest = sha1(b"Hello World!").digest()
        >>> # Sign and verify signature
        >>> sig = do_ecdsa_sign(G, sig_key, digest)
        >>> do_ecdsa_verify(G, ver_key, sig, digest)
        True

    """
    ec_key = _C.EC_KEY_new()
    _check( _C.EC_KEY_set_group(ec_key, G.ecg) )
    _check( _C.EC_KEY_set_private_key(ec_key, priv.bn) )

    ecdsa_sig = _C.ECDSA_do_sign(data, len(data), ec_key)

    r = Bn()
    s = Bn()

    _C.BN_copy(r.bn, ecdsa_sig.r)
    _C.BN_copy(s.bn, ecdsa_sig.s)

    _C.ECDSA_SIG_free(ecdsa_sig)
    _C.EC_KEY_free(ec_key)

    return (r, s)

def do_ecdsa_verify(G, pub, sig, data):
    """A quick function to ECDSA sign a hash.

    Args:
        G (EcGroup): the group in which math is done.
        pub (EcPt): the secret key
        data (str): the string to sign
        sign (Bn, Bn): the (r,s) signature

    Returns:
        bool: A Boolean indicating whether the signature verifies.
    """

    r, s = sig

    ec_key = _C.EC_KEY_new()
    _check( _C.EC_KEY_set_group(ec_key, G.ecg) )
    _check( _C.EC_KEY_set_public_key(ec_key, pub.pt) )

    ec_sig = _C.ECDSA_SIG_new()

    _C.BN_copy(ec_sig.r, r.bn)
    _C.BN_copy(ec_sig.s, s.bn)

    try:
        result = int(_C.ECDSA_do_verify(data, len(data), ec_sig, ec_key))
        if result == -1:
            raise Exception("ECDSA Error")

    finally:
        _C.EC_KEY_free(ec_key)
        _C.ECDSA_SIG_free(ec_sig)

    return bool(result)

def test_ecdsa():
    G = EcGroup()
    priv = G.order().random()
    g = G.generator()
    sig = do_ecdsa_sign(G, priv, b"Hello")
    assert do_ecdsa_verify(G, priv * g, sig, b"Hello")

def test_ecdsa_fail():
    G = EcGroup()
    priv = G.order().random()
    g = G.generator()
    sig = do_ecdsa_sign(G, priv, b"Hello")

    assert not do_ecdsa_verify(G, priv * g, sig, b"Hellx")