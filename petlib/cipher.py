from bindings import _FFI, _C

import pytest


def _check(return_val):
    """Checks the return code of the C calls"""
    if type(return_val) is int and return_val == 1:
      return
    if type(return_val) is bool and return_val == True:
      return

    raise Exception("Cipher exception") 

class Cipher(object):
    """ A class representing a symmetric cipher and mode."""
    def __init__(self, name):
        """Initialize the cipher by name"""
        self.alg = _C.EVP_get_cipherbyname(name)
        if self.alg == _FFI.NULL:
            raise Exception("Unknown cipher: %s" % name )

    def len_IV(self):
        """Return the Initialization Vector length in bytes."""
        return int(self.alg.iv_len)
    def len_key(self):
        """Return the secret key length in bytes."""
        return int(self.alg.key_len)
    def len_block(self):
        """Return the block size in bytes."""
        return int(self.alg.block_size)
    def get_nid(self):
        """Return the OpenSSL nid of the cipher and mode."""
        return int(self.alg.nid)

    def op(self, key, iv, enc=1):
        c_op = CipherOperation()
        _check( len(key) == self.len_key())
        _check( len(iv) == self.len_IV())
        _check( enc in [0,1] )
        _check( _C.EVP_CipherInit_ex(c_op.ctx, 
            self.alg,  _FFI.NULL, key, iv, enc) )
        c_op.cipher = self
        return c_op

    def enc(self, key, iv):
        """Initializes an encryption engine with the cipher with a specific key and Initialization Vector (IV). 
        Returns the CipherOperation engine."""
        return self.op(key, iv, enc=1)

    def dec(self, key, iv):
        """Initializes an decryption engine with the cipher with a specific key and Initialization Vector (IV). 
        Returns the CipherOperation engine."""
        return self.op(key, iv, enc=0)

    def __del__(self):
        pass

class CipherOperation(object):
    def __init__(self):
        self.ctx = _C.EVP_CIPHER_CTX_new()
        _C.EVP_CIPHER_CTX_init(self.ctx)
        self.cipher = None
        
    def control(self, ctype, arg, ptr):
        """Passes an OpenSSL control message to the CipherOpenration engine."""
        ret = int(_C.EVP_CIPHER_CTX_ctrl(self.ctx, ctype, arg, ptr))
        return ret

    def update(self, data):
        """Processes some data, and returns a partial result."""
        block_len = self.cipher.len_block()
        alloc_len = len(data) + block_len - 1
        outl = _FFI.new("int *")
        outl[0] = alloc_len
        out = _FFI.new("unsigned char[]", alloc_len)
        _check( _C.EVP_CipherUpdate(self.ctx, out, outl, data, len(data)))
        ret = str(_FFI.buffer(out)[:int(outl[0])])
        return ret

    def finalize(self):
        """Finalizes the operation and may return some additional data"""
        block_len = self.cipher.len_block()
        alloc_len = block_len
        outl = _FFI.new("int *")
        outl[0] = alloc_len
        out = _FFI.new("unsigned char[]", alloc_len)

        _check( _C.EVP_CipherFinal_ex(self.ctx, out, outl) ) 
        ret = str(_FFI.buffer(out)[:int(outl[0])])
        return ret
        
    def __del__(self):
        _check( _C.EVP_CIPHER_CTX_cleanup(self.ctx) )
        _C.EVP_CIPHER_CTX_free(self.ctx)


def test_aes_init():
    aes = Cipher("AES-128-CBC")
    assert aes.alg != _FFI.NULL
    assert aes.len_IV() == 16
    assert aes.len_block() == 16
    assert aes.len_key() == 16
    assert aes.get_nid() == 419
    del aes


def test_errors():
    with pytest.raises(Exception) as excinfo:
        aes = Cipher("AES-128-XXF")
    assert 'Unknown' in str(excinfo.value)

def test_aes_enc():
    aes = Cipher("AES-128-CBC")
    enc = aes.op(key="A"*16, iv="A"*16)

    ref = "Hello World" * 10000

    ciphertext = enc.update(ref)
    ciphertext += enc.finalize()

    dec = aes.op(key="A"*16, iv="A"*16, enc=0)
    plaintext = dec.update(ciphertext)
    plaintext += dec.finalize()
    assert plaintext == ref

def test_aes_ctr():
    aes = Cipher("AES-128-CTR")
    enc = aes.op(key="A"*16, iv="A"*16)

    ref = "Hello World" * 10000

    ciphertext = enc.update(ref)
    ciphertext += enc.finalize()

    dec = aes.op(key="A"*16, iv="A"*16, enc=0)
    plaintext = dec.update(ciphertext)
    plaintext += dec.finalize()
    assert plaintext == ref

def test_aes_ops():
    aes = Cipher("AES-128-CTR")
    enc = aes.enc(key="A"*16, iv="A"*16)

    ref = "Hello World" * 10000

    ciphertext = enc.update(ref)
    ciphertext += enc.finalize()

    dec = aes.dec(key="A"*16, iv="A"*16)
    plaintext = dec.update(ciphertext)
    plaintext += dec.finalize()
    assert plaintext == ref
