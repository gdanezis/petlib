#!/usr/bin/env python

import os
import platform
import cffi

from ._petlib import ffi, lib

_FFI = ffi
_C = lib

# Store constants
class Const:
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6


_inited = False

def version():
    return str(_FFI.string(_C.SSLeay_version(_C.SSLEAY_VERSION)))

def get_errors():
    errors = []
    err = _C.ERR_get_error()
    while err != 0:
        errors += [ err ]
        err = _C.ERR_get_error()
    return errors

class InitCiphers(object):
    # pylint: disable=global-statement

    def __init__(self):
        global _inited
        self.on = False
        self._C = _C
        if not _inited:
            _C.init_ciphers()
            _inited = True
            self.on = True

    def __del__(self):
        global _inited
        if _inited and self.on and self._C:
            _inited = False
            self._C.cleanup_ciphers()

_ciphers = InitCiphers()

def test_double_load():
    _c2 = InitCiphers()
    del _c2
    ## Nothing bad should happen

def test_version():
    print (version())
    assert version()

def test_errors():
    assert get_errors() == []