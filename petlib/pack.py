"""The module provides functions to pack and unpack petlib Bn, EcGroup, and EcPt
strucures.

Example:
    >>> # Define a custom class, encoder and decoder
    >>> class CustomClass:
    ...     def __eq__(self, other):
    ...         return isinstance(other, CustomClass)
    >>> 
    >>> def enc_CustomClass(obj):
    ...     if isinstance(obj, CustomClass):
    ...         return msgpack.ExtType(10, b'')
    ...     raise TypeError("Unknown type: %r" % (obj,))
    >>>
    >>> def dec_CustomClass(code, data):
    ...     if code == 10:
    ...         return CustomClass()
    ...     return msgpack.ExtType(code, data)
    >>> 
    >>> # Define a structure
    >>> G = EcGroup()
    >>> custom_obj = CustomClass()
    >>> test_data = [G, G.generator(), G.order(), custom_obj]
    >>> 
    >>> # Encode and decode custom structure
    >>> packed = encode(test_data, enc_CustomClass)
    >>> x = decode(packed, dec_CustomClass)
    >>> assert x == test_data

"""

import msgpack

from .ec import EcGroup, EcPt
from .bn import Bn

__all__ = ["encode", "decode"]


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

    # Serialize EcGroup objects
    elif isinstance(obj, EcGroup):
        nid = obj.nid()
        packed_nid = msgpack.packb(nid)
        return msgpack.ExtType(1, packed_nid)

    # Serialize EcPt objects
    elif isinstance(obj, EcPt):
        nid = obj.group.nid()
        data = obj.export()
        packed_nid = msgpack.packb((nid, data))
        return msgpack.ExtType(2, packed_nid)

    raise TypeError("Unknown type: %r" % (obj,))

def make_encoder(out_encoder=None):
    if out_encoder is None:
        return default
    else:
        def new_encoder(obj):
            try:
                encoded = default(obj)
                return encoded
            except:
                return out_encoder(obj)
        return new_encoder

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

def make_decoder(custom_decoder=None):
    if custom_decoder is None:
        return ext_hook
    else:
        def new_decoder(code, data):
            out = ext_hook(code, data)
            if not isinstance(out, msgpack.ExtType):
                return out
            else:
                return custom_decoder(code, data)
        return new_decoder

def encode(structure, custom_encoder=None):
    """ Encode a structure containing petlib objects to a binary format. May define a custom encoder for user classes. """
    encoder = make_encoder(custom_encoder)
    packed_data = msgpack.packb(structure, default=encoder, use_bin_type=True)
    return packed_data
    
def decode(packed_data, custom_decoder=None):
    """ Decode a binary byte sequence into a structure containing pelib objects. May define a custom decoder for custom classes. """
    decoder = make_decoder(custom_decoder)
    structure = msgpack.unpackb(packed_data, ext_hook=decoder, encoding='utf-8')
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

def test_enc_dec_custom():

    # Define a custom class, encoder and decoder
    class CustomClass:
        def __eq__(self, other):
            return isinstance(other, CustomClass)

    def enc_CustomClass(obj):
        if isinstance(obj, CustomClass):
            return msgpack.ExtType(10, b'')
        raise TypeError("Unknown type: %r" % (obj,))

    def dec_CustomClass(code, data):
        if code == 10:
            return CustomClass()

        return msgpack.ExtType(code, data)

    # Define a structure
    G = EcGroup()
    custom_obj = CustomClass()
    test_data = [G, G.generator(), G.order(), custom_obj]
    
    # Encode and decode custom structure
    packed = encode(test_data, enc_CustomClass)
    x = decode(packed, dec_CustomClass)
    assert x == test_data

def test_streaming():

    # Define a custom class, encoder and decoder
    class CustomClass:
        def __eq__(self, other):
            return isinstance(other, CustomClass)

    def enc_CustomClass(obj):
        if isinstance(obj, CustomClass):
            return msgpack.ExtType(10, b'')
        raise TypeError("Unknown type: %r" % (obj,))

    def dec_CustomClass(code, data):
        if code == 10:
            return CustomClass()

        return msgpack.ExtType(code, data)

    # Define a structure
    G = EcGroup()
    custom_obj = CustomClass()
    test_data = [G, G.generator(), G.order(), custom_obj]
    packed1 = encode(test_data, enc_CustomClass)
    packed2 = encode(test_data, enc_CustomClass)

    data = packed1 + packed2
    
    decoder = make_decoder(dec_CustomClass)
    Up = msgpack.Unpacker(ext_hook=decoder)
    Up.feed(data)
    for o in Up:
        print(o)
        assert o == test_data
