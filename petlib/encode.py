from .ec import EcGroup, EcPt
from .bn import Bn

import json
from os import urandom
from base64 import b64encode, b64decode

class B(object):
    def __init__(self, b):
        assert isinstance(b, (bytes, str))
        self.b = b

class CryptoEnc(json.JSONEncoder):
    """
    A JSON encoder that knows about Bn and EcPt
    """

    def __init__(self):
        json.JSONEncoder.__init__(self)

    def default(self, o): # pylint: disable=method-hidden
        if isinstance(o, Bn):
            return {
                '_t': "Bn",
                'bn': b64encode(o.binary()).strip().decode("utf8")
                }

        if isinstance(o, EcPt):
            return {
                '_t': "EcPt",
                'Gid': o.group.nid(),
                'pt': b64encode(o.export()).strip().decode("utf8")
                }

        if isinstance(o, B):
            return {
                '_t': "_b64",
                'b': b64encode(o.b).strip().decode("utf8")
                }

        return json.JSONEncoder.default(self, o)


class CryptoDec(json.JSONDecoder):
    """
    A JSON Deconder that knows about Bn and EcPt
    """

    def __init__(self, keepB=False):
        json.JSONDecoder.__init__(self, object_hook=self.dict_to_object)
        self.keepB = keepB

    def dict_to_object(self, d):
        if u"_t" in d and d[u"_t"] == u"Bn":
            return  Bn.from_binary(b64decode(d[u"bn"]))

        if u"_t" in d and d[u"_t"] == u"EcPt":
            G = EcGroup(int(d[u"Gid"]))
            pt_s = b64decode(d[u"pt"])
            return EcPt.from_binary(bytes(pt_s), G)

        if u"_t" in d and d[u"_t"] == u"_b64":
            if not self.keepB:
                return b64decode(d[u"b"])
            else:
                return B(b64decode(d[u"b"]))
        return d

def test_encoder_bn():
    e = CryptoEnc()
    s = e.encode([Bn(1), Bn(2), B(urandom(160))])
    #print "length:",len(s)
    x = CryptoDec().decode(s)
    assert x[0] == 1 and x[1] == 2
    
def test_encoder_ec():
    G = EcGroup()
    e = CryptoEnc()
    x = B(urandom(160))
    s = e.encode([G.generator(), G.generator(), x])
    y = CryptoDec().decode(s)
    assert y[2] == x.b

def test_encoder_keepB():
    e = CryptoEnc()
    x = B(urandom(160))
    s = e.encode([x, x, x])
    y = CryptoDec(keepB=True).decode(s)
    assert y[2].b == x.b

