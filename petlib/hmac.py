from bindings import _FFI, _C
from functools import wraps
from copy import copy
from binascii import hexlify

import pytest

def _check(return_val):
    """Checks the return code of the C calls"""
    if type(return_val) is int and return_val == 1:
      return
    if type(return_val) is bool and return_val == True:
      return

    raise Exception("HMAC exception") 


class Hmac:
    def __init__(self, name, key):
        md = _C.EVP_get_digestbyname(name)
        if md == _FFI.NULL:
            raise Exception("HMAC Error loading function %s", name)

        self.outsize = _C.EVP_MD_size(md)
        self.mac_ctx = _FFI.new("HMAC_CTX *")
        _C.HMAC_CTX_init(self.mac_ctx)
        _check(_C.HMAC_Init_ex(self.mac_ctx, key, len(key), md, _FFI.NULL))
        self.active = True

    def update(self, data):
        if not self.active:
            raise Exception("HMAC already finalized!")
        _check(_C.HMAC_Update(self.mac_ctx, data, len(data)))

    def digest(self):
        if not self.active:
            raise Exception("HMAC already finalized!")
        self.active = False
        out_md = _FFI.new("unsigned char[]", self.outsize)
        out_len = _FFI.new("unsigned int *")
        _check(_C.HMAC_Final(self.mac_ctx, out_md, out_len))

        if int(out_len[0]) != self.outsize:
            raise Exception("HMAC Unexpected length")

        return str(_FFI.buffer(out_md))


    def __del__(self):
        _C.HMAC_CTX_cleanup(self.mac_ctx)
        

def test_init():
    h = Hmac("md5", "Hello")
    h.update("hello")
    d = h.digest()

def test_vectors():
    """
    Key =          4a656665                          ("Jefe")
   Data =         7768617420646f2079612077616e7420  ("what do ya want ")
                  666f72206e6f7468696e673f          ("for nothing?")

   HMAC-SHA-224 = a30e01098bc6dbbf45690f3a7e9e6d0f
                  8bbea2a39e6148008fd05e44
   HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c7
                  5a003f089d2739839dec58b964ec3843
   HMAC-SHA-384 = af45d2e376484031617f78d2b58a6b1b
                  9c7ef464f5a01b47e42ec3736322445e
                  8e2240ca5e69e2c78b3239ecfab21649
   HMAC-SHA-512 = 164b7a7bfcf819e2e395fbe73b56e0a3
                  87bd64222e831fd610270cd7ea250554
                  9758bf75c05a994a6d034f65f8f0e6fd
                  caeab1a34d4a6b4b636e070a38bce737
    """

    h = Hmac("sha512", "Jefe")
    h.update("what do ya want ")
    h.update("for nothing?")
    d = h.digest()
    assert hexlify(d) == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
