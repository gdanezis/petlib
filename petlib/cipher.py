from bindings import _FFI, _C
from functools import wraps
from copy import copy
from binascii import hexlify

import pytest

class Cipher(object):
	def __init__(self, name):
		self.alg = _C.EVP_get_cipherbyname(name)
		if self.alg == _FFI.NULL:
			raise Exception("Unknown cipher: %s" % name )

	def len_IV(self):
		return int(self.alg.iv_len)
	def len_key(self):
		return int(self.alg.key_len)
	def len_block(self):
		return int(self.alg.block_size)


	def __del__(self):
		pass

def test_aes():
	aes = Cipher("AES-128-CBC")
	assert aes.alg != _FFI.NULL
	assert aes.len_IV() == 16
	assert aes.len_block() == 16
	assert aes.len_key() == 16
	assert False