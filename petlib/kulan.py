from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.cipher import Cipher

from hashlib import sha1

import json
from os import urandom

# Cryptographic primitives used:
# AES-128-GCM (IV=16, TAG=16)
# 
# NIST p224

def derive_2DH_sender(G, priv, pub1, pub2):
    md = sha1()
    md.update((priv * pub1).export())
    md.update((priv * pub2).export())
    return md.digest()

def derive_2DH_receiver(G, pub, priv1, priv2):
    md = sha1()
    md.update((priv1 * pub).export())
    md.update((priv2 * pub).export())
    return md.digest()


def derive_3DH_sender(G, priv1, priv2, pub1, pub2):
    md = sha1()
    md.update((priv1 * pub2).export())
    md.update((priv2 * pub1).export())
    md.update((priv2 * pub2).export())
    return md.digest()

def derive_3DH_receiver(G, pub1, pub2, priv1, priv2):
    md = sha1()
    md.update((priv2 * pub1).export())
    md.update((priv1 * pub2).export())
    md.update((priv2 * pub2).export())
    return md.digest()


def test_2DH():
    G = EcGroup()
    g = G.generator()
    o = G.order()

    priv1 = o.random()
    priv2 = o.random()
    priv3 = o.random()

    k1 = derive_2DH_sender(G, priv1, priv2 * g, priv3 * g)
    k2 = derive_2DH_receiver(G, priv1 * g, priv2, priv3)

    assert k1 == k2

def test_3DH():
    G = EcGroup()
    g = G.generator()
    o = G.order()

    priv1 = o.random()
    pub1 = priv1 * g 
    priv2 = o.random()
    pub2 = priv2 * g
    priv3 = o.random()
    pub3 = priv3 * g
    priv4 = o.random()
    pub4 = priv4 * g

    k1 = derive_3DH_sender(G, priv1, priv2, pub3, pub4)
    k2 = derive_3DH_receiver(G, pub1, pub2, priv3, priv4)
    assert k1 == k2


## Define a "steady state" channel:
#  - Use a shared key for channel confidentiality and integrity.
#  - Use "ecdsa" for authenticaity (ephemeral)

class KulanClient(object):

    def __init__(self, G, name, priv, pki):
        # Maths
        self.G = G
        self.g = self.G.generator()
        self.order = self.G.order()

        ## Store keys
        self.priv = priv
        self.pub = priv * self.g

        self.pki = pki
        self.name = name

        # Which channel are we in?
        self.admins = []
        self.members = []

        # Channel key stores
        self.Ks = [] 

        ## Generate an ephemeral signature key
        self.priv_sign = self.order.random()
        self.pub_sign = self.priv_sign * self.g

        ## Storage for short term dictionaries
        self.current_dict = {"me": self.pub_sign}

        ## Generate an ephemeral signature key
        self.priv_enc = self.order.random()
        self.pub_enc = self.priv_enc * self.g

        self.aes = Cipher("aes-128-gcm")

    def broadcast_encrypt(self, plaintext):
        sym_key = urandom(16)
        iv = urandom(16)

        msg = [self.pub.export(), self.pub_enc.export(), iv]

        msg2 = []
        for name, (pub1, pub2) in self.pki.items():
            K = derive_3DH_sender(self.G, self.priv, self.priv_enc, pub1, pub2)            

            enc = self.aes.enc(key=K[:16], iv=iv)
            ciphertext = enc.update(sym_key)
            enc.finalize()
            tag = enc.get_tag(16)

            msg2 += [(ciphertext, tag)]

        msg += [msg2]
        inner_msg = json.dumps([self.name.encode("base64"), self.pub_sign.export().encode("base64")])
        
        enc = self.aes.enc(key=sym_key, iv=iv)
        ciphertext = enc.update(inner_msg)
        enc.finalize()
        tag = enc.get_tag(16)

        msg += [(ciphertext, tag)]

        return msg

    def broadcast_decrypt(self, msgs):
        pub1 = EcPt.from_binary(msgs[0], self.G)
        pub2 = EcPt.from_binary(msgs[1], self.G)
        iv = msgs[2]

        K = derive_3DH_receiver(self.G, pub1, pub2, self.priv, self.priv_enc)

        for cip, tag in msgs[3]:
            try:
                dec = self.aes.dec(key=K[:16], iv=iv)
                sym_key = dec.update(cip)
                dec.set_tag(tag)
                dec.finalize()
                break
            except:
                sym_key = None

        ## Is no decryption is available bail-out
        if not sym_key:
            raise Exception("No decryption")

        ciphertext2, tag2 = msgs[-1] 
        dec = self.aes.dec(key=sym_key, iv=iv)
        plaintext = dec.update(ciphertext2)
        dec.set_tag(tag2)
        dec.finalize()

        [name, sig_key] = json.loads(plaintext)
        name = name.decode("base64")
        sig_key = EcPt.from_binary(sig_key.decode("base64"), self.G)

        return (name, sig_key)
            

    def steady_encrypt(self, plaintext):
        assert len(self.Ks) > 0

        ## Sign using ephemeral signature
        md = sha1()
        md.update(self.Ks[-1])
        md.update(plaintext)
        md = md.digest()

        # Note: include the key here to bing the signature 
        # to the encrypted channel defined by this key. 
        r, s = do_ecdsa_sign(self.G, self.priv_sign, md)
        inner_message = [self.name, plaintext, hex(r), hex(s)]
        plain_inner = json.dumps(inner_message)
        
        ## Encrypt using AEC-GCM
        iv = urandom(16)
        enc = self.aes.op(key=self.Ks[-1], iv=iv)
        ciphertext = enc.update(plain_inner)
        enc.finalize()
        tag = enc.get_tag(16)

        return json.dumps([iv.encode("base64"), ciphertext.encode("base64"), tag.encode("base64")])


    def steady_decrypt(self, ciphertext):
        assert len(self.Ks) > 0

        [iv, ciphertext, tag] = json.loads(ciphertext)
        iv, ciphertext, tag = iv.decode("base64"), \
                              ciphertext.decode("base64"), \
                              tag.decode("base64")

        ## Decrypt and check integrity
        dec = self.aes.dec(key=self.Ks[-1], iv=iv)
        plaintext = dec.update(ciphertext)
        dec.set_tag(tag)
        dec.finalize()

        ## Check signature
        [xname, xplain, xr, xs] = json.loads(plaintext)

        md = sha1()
        md.update(self.Ks[-1])
        md.update(str(xplain))
        md = md.digest()
        
        sig = Bn.from_hex(str(xr)), Bn.from_hex(str(xs))
        pub = self.current_dict[str(xname)]
        if not do_ecdsa_verify(self.G, pub, sig, str(md)):
            return None

        return (str(xname), str(xplain))


## Define an "introduction message":
#  - Use 2DH to derive parwise shared keys.
#  - Use MACs to provide integirty and authenticity.

## Define client state
#  - Own long-term secret key.
#  - Own short-term secret key.
#  - Short-tem signature key.
#  - Link to name <-> key map.
#  - Map of names in the channel.

def test_steady():
    G = EcGroup()
    g = G.generator()
    x = G.order().random()
    pki = {"me":(x * g, x * g)}
    client = KulanClient(G, "me", x, pki)

    ## Mock some keys
    client.Ks += [urandom(16)]

    # Decrypt a small message
    ciphertext = client.steady_encrypt("Hello World!")
    client.steady_decrypt(ciphertext)

    # Decrypt a big message
    ciphertext = client.steady_encrypt("Hello World!"*10000)
    client.steady_decrypt(ciphertext)

    # decrypt an empty string
    ciphertext = client.steady_encrypt("")
    client.steady_decrypt(ciphertext)

    # Time it
    import time
    t0 = time.clock()
    for _ in range(1000):
        ciphertext = client.steady_encrypt("Hello World!"*10)
        client.steady_decrypt(ciphertext)
    t = time.clock() - t0

    print
    print " - %2.2f operations / sec" % (1.0 / (t / 1000))

def test_broad():
    G = EcGroup()
    g = G.generator()
    x = G.order().random()

    a = G.order().random()
    puba = a * g
    b = G.order().random()
    pubb = b * g
    c = G.order().random()
    pubc = c * g

    a2 = G.order().random()
    puba2 = a2 * g
    b2 = G.order().random()
    pubb2 = b2 * g
    c2 = G.order().random()
    pubc2 = c2 * g


    pki = {"a":(puba,puba2) , "b":(pubb, pubb2), "c":(pubc, pubc2)}
    client = KulanClient(G, "me", x, pki)

    msgs = client.broadcast_encrypt("Hello!")

    pki2 = { "b":(pubb, pubb2), "c":(pubc, pubc2)}
    dec_client = KulanClient(G, "a", a, pki2)

    dec_client.priv_enc = a2
    dec_client.pub_enc = puba2

    namex, keysx = dec_client.broadcast_decrypt(msgs)
    assert namex == "me"
    # print msgs