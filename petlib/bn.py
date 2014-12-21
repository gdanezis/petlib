from bindings import _FFI, _C
from functools import wraps
from copy import copy
from binascii import hexlify

import pytest

def force_Bn(n):
  """A decorator that coerces the nth input to be a Big Number"""

  def convert_nth(f):
    @wraps(f)  
    def new_f(*args, **kwargs):
      if not n < len(args):
        return f(*args, **kwargs)

      if type(args[n]) == Bn:
        return f(*args, **kwargs)
      
      if type(args[n]) == int:
        r = Bn(args[n])
        new_args = list(args)
        new_args[n] = r
        return f(*tuple(new_args), **kwargs)

      return NotImplemented
    return new_f
  return convert_nth

def _check(return_val):
    """Checks the return code of the C calls"""
    if type(return_val) is int and return_val == 1:
      return
    if type(return_val) is bool and return_val == True:
      return

    raise Exception("BN exception") 

class Bn(object):
  """The core Big Number class. 
     It supports all comparisons (<, <=, ==, !=, >=, >),
     arithemtic operations (+, -, %, /, divmod, pow) 
     and copy operations (copy and deep copy). The right-hand 
     side operand may be a small native python integer (<2^64). """

  # We know this class will keep minimal state
  __slots__ = ['bn']

  ## -- static methods  
  @staticmethod
  def from_decimal(sdec):
    """
    Creates a Big Number from a decimal string.
    
    Args:
      sdec (string) -- numeric string possibly starting with minus.
    """

    ptr = _FFI.new("BIGNUM **")
    read_bytes = _C.BN_dec2bn(ptr, sdec)
    if read_bytes != len(sdec):
      raise Exception("BN Error")

    ret = Bn()
    _C.BN_copy(ret.bn, ptr[0])
    _C.BN_clear_free(ptr[0])
    return ret

  @staticmethod
  def from_hex(shex):
    """
    Creates a Big Number from a hexadecimal string.
    
    Args:
      shex (string) -- hex (0-F) string possibly starting with minus.
    """

    ptr = _FFI.new("BIGNUM **")
    read_bytes = _C.BN_hex2bn(ptr, shex)
    if read_bytes != len(shex):
      raise Exception("BN Error")

    ret = Bn()
    _C.BN_copy(ret.bn, ptr[0])
    _C.BN_clear_free(ptr[0])
    return ret

  @staticmethod
  def from_binary(sbin):
    """Creates a Big Number from a binary string. Only positive values are read.
    
    Args:
      sbin (string) -- binary (00-FF) string. 
    """
    ret = Bn()
    _C.BN_bin2bn(sbin, len(sbin), ret.bn)
    return ret

  @staticmethod
  def get_prime(bits, safe=1):
    """
    Builds a prime Big Number of length bits.

    Args:
        bits (int) -- the number of bits.
        safe (int) -- 1 for a safe prime, otherwise 0.
    
    """
    _check( 0 < bits < 10000 )
    _check( safe in [0,1] )
    
    ret = Bn()
    _check( _C.BN_generate_prime_ex(ret.bn, bits, safe, _FFI.NULL, _FFI.NULL, _FFI.NULL) )
    return ret


  ## -- methods

  def __init__(self, num=0):
    'Allocate a Big Number structure, initialized with num or zero'
    _check( 0 <= abs(num) <= 2**(64-1) )
    self.bn = _C.BN_new()

    # Assign
    if num != 0:
      _check(_C.BN_set_word(self.bn, abs(num)))

    if num < 0:
      self._set_neg(1)

  def _set_neg(self, sign=1):
    """Sets the sign to "-" (1) or "+" (0)"""
    _check( sign == 0 or sign == 1 )
    _C.BN_set_negative(self.bn, sign)

  def __copy__(self):
    'Copies the big number. Support for copy module'
    other = Bn()
    _C.BN_copy(other.bn, self.bn)
    return other

  def __deepcopy__(self, memento):
    'Deepcopy is the same as copy' 
    return self.__copy__()

  def __del__(self):
    'Deallocate all resources of the big number'
    _C.BN_clear_free(self.bn)

  @force_Bn(1)
  def __cmp__(self, other):
    'Internal comparison function' 
    _check( type(other) == Bn )
    sig = int(_C.BN_cmp(self.bn, other.bn))
    return sig

  def nonzero(self):
    'Turn bn into boolean. False if zero, True otherwise.' 
    return self.__nonzero__()

  def __nonzero__(self):
    'Turn into boolean' 
    return not (self == Bn(0))

  ## Export in different representations

  def repr(self):
    'The representation of the number as a decimal string'
    return self.__repr__()

  def __repr__(self):
    'The representation of the number as a decimal string'
    buf =  _C.BN_bn2dec(self.bn);
    s = str(_FFI.string(buf))
    _C.OPENSSL_free(buf)
    return s

  def int(self):
    """A native python integer representation of the Big Number.
       Synonym for int(bn).
    """
    return self.__int__()

  def __int__(self):
    """A native python integer representation of the Big Number"""
    return int(self.__repr__())

  def __index__(self):
    """A native python integer representation of the Big Number"""
    return int(self.__repr__())

  def hex(self):
    """The representation of the string in hexadecimal. 
    Synonym for hex(n)."""
    return self.__hex__()

  def __hex__(self):
    """The representation of the string in hexadecimal"""
    buf =  _C.BN_bn2hex(self.bn);
    s = str(_FFI.string(buf))
    _C.OPENSSL_free(buf)
    return s

  def binary(self):
    """Returns the binary representation of the absolute value of the Big 
    Number. You need to extact the sign separately."""
    if self < 0:
        raise Exception("Cannot represent negative numbers")
    size = _C._bn_num_bytes(self.bn);
    bin_string = _FFI.new("unsigned char[]", size)
    _check( _C.BN_bn2bin(self.bn, bin_string) )
    return str(_FFI.buffer(bin_string)[:])

  def random(self):
    """Returns a cryptographically strong random number 0 <= rnd < self."""
    rnd = Bn()
    _check( _C.BN_rand_range(rnd.bn, self.bn) )
    return rnd


  ## ---------- Arithmetic --------------

  def int_add(self, other):
    """Returns the sum of this number with another. Synonym for self + other."""
    return self.__add__(other)

  @force_Bn(1)
  def __add__(self, other):
    r = Bn()
    _check(_C.BN_add(r.bn, self.bn, other.bn))
    return r

  def int_sub(self, other):
    """Returns the difference between this number and another. 
    Synonym for self - other."""

  @force_Bn(1)
  def __sub__(self, other):
    r = Bn()
    _check(_C.BN_sub(r.bn, self.bn, other.bn))
    return r

  def int_mul(self, other):
    """Returns the product of this number with another.
    Synonym for self * other."""
    return self.__mul__(other)

  @force_Bn(1)
  def __mul__(self, other):
    try:
      bnctx = _C.BN_CTX_new()
      r = Bn()
      _check(_C.BN_mul(r.bn, self.bn, other.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return r

  @force_Bn(1)
  @force_Bn(2)
  def mod_add(self, other, m):
    """
    mod_add(other, m)
    Returns the sum of self and other modulo m."""
    try:
      bnctx = _C.BN_CTX_new()
      r = Bn()
      _check(_C.BN_mod_add(r.bn, self.bn, other.bn, m.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return r

  @force_Bn(1)
  @force_Bn(2)
  def mod_sub(self, other, m):
    """
    mod_sub(other, m)
    Returns the difference of self and other modulo m."""
    try:
      bnctx = _C.BN_CTX_new()
      r = Bn()
      _check(_C.BN_mod_sub(r.bn, self.bn, other.bn, m.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return r

  @force_Bn(1)
  @force_Bn(2)
  def mod_mul(self, other, m):
    """
    mod_mul(other, m)
    Return the product of self and other modulo m."""
    try:
      bnctx = _C.BN_CTX_new()
      r = Bn()
      _check(_C.BN_mod_mul(r.bn, self.bn, other.bn, m.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return r

  def divmod(self, other):
    """Returns the integer division and remaider of this number by another.
    Synonym for (div, mod) = divmod(self, other)"""
    return self.__divmod__(other)

  @force_Bn(1)
  def __divmod__(self, other):
    try:
      bnctx = _C.BN_CTX_new()
      dv = Bn()
      rem = Bn()
      _check(_C.BN_div(dv.bn, rem.bn, self.bn, other.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return (dv, rem)

  def int_div(self, other):
    """Returns the integer division of this number by another. 
    Synonym of self / other"""
    return self.__div__(other)

  @force_Bn(1)
  def __div__(self, other):
    dv, _ = divmod(self, other)
    return dv

  def mod(self, other):
    """Returns the remainder of this number modulo another.
    Synonym for self % other"""
    return self.__mod__(other)

  @force_Bn(1)
  def __mod__(self, other):
    try:
      bnctx = _C.BN_CTX_new()
      rem = Bn()
      _check(_C.BN_nnmod(rem.bn, self.bn, other.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return rem

  @force_Bn(1)
  def __truediv__(self, other):
    return self.__div__(other)

  @force_Bn(1)
  def __floordiv__(self, other):
    return self.__div__(other)

  def pow(self, other, modulo=None):
    """Returns the number raised to the power other optionally modulo a third number. 
    Synonym with powe(self, other, modulo)"""

  @force_Bn(1)
  @force_Bn(2)
  def __pow__(self, other, modulo=None):
    try:
      bnctx = _C.BN_CTX_new()
      res = Bn()
      if modulo is None:
        _check(_C.BN_exp(res.bn, self.bn, other.bn, bnctx))
      else:
        _check(_C.BN_mod_exp(res.bn, self.bn, other.bn, modulo.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return res

  @force_Bn(1)
  def mod_inverse(self, m):
    """
    mod_inverse(m)
    Compute the inverse mod m, such that self * res == 1 mod m."""

    try:
      bnctx = _C.BN_CTX_new()
      res = Bn()
      err = _C.BN_mod_inverse(res.bn, self.bn, m.bn, bnctx)
      if err == _FFI.NULL:
        raise Exception("No inverse")
    finally:
      _C.BN_CTX_free(bnctx)
    return res

  def is_prime(self):
    """Returns True if the number is prime, with negligible prob. of error."""
    
    res = int(_C.BN_is_prime_ex(self.bn, 0, _FFI.NULL, _FFI.NULL))
    if res == 0:
      return False
    if res == 1:
      return True
    raise Exception("Primality test failure %s" % int(res) )

  def num_bits(self):
    """Returns the number of bits representing this Big Number"""
    return int(_C.BN_num_bits(self.bn))

  def int_neg(self):
    """Returns the negative of this number. Synonym with -self"""
    return self.__neg__()

  # Implement negative 
  def __neg__(self):
    zero = Bn(0)
    ret = copy(self)
    if ret >= zero:
      ret._set_neg(1)
    else:
      ret._set_neg(0)
    return ret

  
## Unsuported
# object.__lshift__(self, other)
# object.__rshift__(self, other)
# object.__and__(self, other)
# object.__xor__(self, other)
# object.__or__(self, other)

# ---------- Tests ------------

def test_bn_constructors():
  assert Bn.from_decimal("100") == 100
  assert Bn.from_decimal("-100") == -100

  with pytest.raises(Exception) as excinfo:
    Bn.from_decimal("100ABC")
  assert 'BN Error' in str(excinfo.value)

  with pytest.raises(Exception) as excinfo:
    Bn.from_hex("100ABCZ")
  assert 'BN Error' in str(excinfo.value)

  assert Bn.from_hex(hex(Bn(-100))) == -100
  assert Bn(15).hex() == hex(Bn(15))

  with pytest.raises(Exception) as excinfo:
    Bn(-100).binary()
  assert 'negative' in str(excinfo.value)

  #assert Bn.from_binary(Bn(-100).binary()) == 100
  assert Bn.from_binary(Bn(100).binary()) == Bn(100)
  assert Bn.from_binary(Bn(100).binary()) == 100

  with pytest.raises(Exception) as excinfo:
    _check(False)
  assert 'BN' in str(excinfo.value)


  #assert Bn.from_binary(Bn(-100).binary()) != Bn(50)
  assert int(Bn(-100)) == -100

  assert repr(Bn(5)) == Bn(5).repr() == "5"
  assert range(10)[Bn(4)] == 4

  d = {Bn(5): 5, Bn(6):6}


def test_bn_prime():
  p = Bn.get_prime(512)
  assert p > Bn(0)
  assert p.is_prime()
  assert not Bn(16).is_prime()
  assert p.num_bits() > 500

def test_bn_arithmetic():
  assert (Bn(1) + Bn(1) == Bn(2))
  assert (Bn(1).int_add(Bn(1)) == Bn(2))

  assert (Bn(1) + 1 == Bn(2))
  # assert (1 + Bn(1) == Bn(2))
  
  assert (Bn(1) + Bn(-1) == Bn(0))
  assert (Bn(10) + Bn(10) == Bn(20))
  assert (Bn(-1) * Bn(-1) == Bn(1))
  assert (Bn(-1).int_mul(Bn(-1)) == Bn(1))

  assert (Bn(10) * Bn(10) == Bn(100))
  assert (Bn(10) - Bn(10) == Bn(0))
  assert (Bn(10) - Bn(100) == Bn(-90))
  assert (Bn(10) + (-Bn(10)) == Bn(0))
  s = -Bn(100)
  assert (Bn(10) + s == Bn(-90))
  assert (Bn(10) - (-Bn(10)) == Bn(20))
  assert -Bn(-10) == 10
  assert Bn(-10).int_neg() == 10

  assert divmod(Bn(10), Bn(3)) == (Bn(3), Bn(1))
  assert Bn(10).divmod(Bn(3)) == (Bn(3), Bn(1))

  assert Bn(10) / Bn(3) == Bn(3)
  assert Bn(10) // Bn(3) == Bn(3)
  assert Bn(10).int_div(Bn(3)) == Bn(3)

  assert Bn(10) % Bn(3) == Bn(1)
  assert Bn(10).mod(Bn(3)) == Bn(1)

  
  assert Bn(2) ** Bn(8) == Bn(2 ** 8)
  assert pow(Bn(2), Bn(8), Bn(27)) == Bn(2 ** 8 % 27)

  assert pow(Bn(2), 8, 27) == 2 ** 8 % 27

  assert Bn(3).mod_inverse(16) == 11
  

  with pytest.raises(Exception) as excinfo:
    Bn(3).mod_inverse(0)
  assert 'No inverse' in str(excinfo.value)


  assert Bn(10).mod_add(10, 15) == (10 + 10) % 15
  assert Bn(10).mod_sub(100, 15) == (10 - 100) % 15
  assert Bn(10).mod_mul(10, 15) == (10 * 10) % 15
  assert Bn(-1).nonzero()


def test_bn_allocate():
  # Test allocation
  n = Bn()
  n0 = Bn(10)
  assert True

  assert str(Bn()) == "0"
  assert str(Bn(1)) == "1"
  assert str(Bn(-1)) == "-1"

  assert hex(Bn(15)) == "0F"
  assert hex(Bn(-15)) == "-0F"

  assert int(Bn(5)) == 5
  assert Bn(5).int() == 5


  assert 0 <= Bn(15).random() < 15

  # Test copy
  import copy
  o0 = copy.copy(n0)
  o1 = copy.deepcopy(n0)

  assert o0 == n0
  assert o1 == n0

  # Test nonzero
  assert not Bn()
  assert not Bn(0)
  assert Bn(1)
  assert Bn(100)

def test_bn_cmp():
  assert Bn(1) < Bn(2)
  assert Bn(1) <= Bn(2)
  assert Bn(2) <= Bn(2)
  assert Bn(2) == Bn(2)
  assert Bn(2) <= Bn(3)
  assert Bn(2) < Bn(3)

def test_check():
  with pytest.raises(Exception) as excinfo:
    _check(False)
  assert 'BN' in str(excinfo.value)

  with pytest.raises(Exception) as excinfo:
    _check(-1)
  assert 'BN' in str(excinfo.value)

  with pytest.raises(Exception) as excinfo:
    _check(0)      
  assert 'BN' in str(excinfo.value)