import msgpack

from .ec import EcGroup, EcPt
from .bn import Bn


def default(obj):
    # Serialize Bn objects
    if isinstance(obj, Bn):
        if obj < 0:
            neg = b"-"
            data = (-obj).binary()
        else:
            neg = b"+"
            data = obj.binary()
        return msgpack.ExtType(0, neg + data)

    elif isinstance(obj, EcGroup):
        nid = obj.nid()
        packed_nid = msgpack.packb(nid)
        return msgpack.ExtType(1, packed_nid)

    elif isinstance(obj, EcPt):
        nid = obj.group.nid()
        data = obj.export()
        packed_nid = msgpack.packb((nid, data))
        return msgpack.ExtType(2, packed_nid)

    raise TypeError("Unknown type: %r" % (obj,))


def ext_hook(code, data):

    # Decode Bn types
    if code == 0:
        num = Bn.from_binary(data[1:])
        # Accomodate both Python 2 and Python 3
        if data[0] == ord("-") or data[0] == "-":
            return -num
        return num

    # Decode EcGroup
    elif code == 1:
        nid = msgpack.unpackb(data)
        return EcGroup(nid)

    # Decode EcPt
    elif code == 2:
        nid, ptdata = msgpack.unpackb(data)
        return EcPt.from_binary(ptdata, EcGroup(nid))

    # Other
    return msgpack.ExtType(code, data)

def encode(structure):
    """ Encode a structure containing petlib objects to a binary format """
    packed_data = msgpack.packb(structure, default=default, use_bin_type=True)
    return packed_data
    
def decode(packed_data):
    """ Decode a binary byte sequence into a structure containing pelib objects """
    structure = msgpack.unpackb(packed_data, ext_hook=ext_hook, encoding='utf-8')
    return structure

# --- TESTS ---

def test_basic():
    x = [b'spam', u'egg']
    packed = msgpack.packb(x, use_bin_type=True)
    y = msgpack.unpackb(packed, encoding='utf-8')
    assert x == y

def test_bn():
    bn1, bn2 = Bn(1), Bn(2)
    test_data = [bn1, bn2, -bn1, -bn2]
    packed = msgpack.packb(test_data, default=default, use_bin_type=True)
    x = msgpack.unpackb(packed, ext_hook=ext_hook, encoding='utf-8')
    assert x == test_data

def test_ecgroup():
    G = EcGroup()
    test_data = [G]
    packed = msgpack.packb(test_data, default=default, use_bin_type=True)
    x = msgpack.unpackb(packed, ext_hook=ext_hook, encoding='utf-8')
    assert x == test_data

def test_ecpt():
    G = EcGroup()
    test_data = [G.generator()]
    packed = msgpack.packb(test_data, default=default, use_bin_type=True)
    x = msgpack.unpackb(packed, ext_hook=ext_hook, encoding='utf-8')
    assert x == test_data

def test_mixed():
    G = EcGroup()
    test_data = [G, G.generator(), G.order()]
    packed = msgpack.packb(test_data, default=default, use_bin_type=True)
    x = msgpack.unpackb(packed, ext_hook=ext_hook, encoding='utf-8')
    assert x == test_data

def test_enc_dec():
    G = EcGroup()
    test_data = [G, G.generator(), G.order()]
    packed = encode(test_data)
    x = decode(packed)
    assert x == test_data

def test_enc_dec_dict():
    G = EcGroup()
    test_data = {G.order():[G, G.generator()]} #, G.generator():"1", "2":G.order()}
    packed = encode(test_data)
    x = decode(packed)
    assert x[G.order()] == test_data[G.order()]
