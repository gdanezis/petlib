#!/usr/bin/env python
import cffi
from copy import copy
from binascii import hexlify

_FFI = cffi.FFI()

_FFI.cdef("""

void OPENSSL_free(void*);

typedef enum {
  /* values as defined in X9.62 (ECDSA) and elsewhere */
  POINT_CONVERSION_COMPRESSED = 2,
  POINT_CONVERSION_UNCOMPRESSED = 4,
  POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BIGNUM;
typedef ... BN_GENCB;


EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int EC_GROUP_get_curve_name(const EC_GROUP *group);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);


typedef ... EC_KEY;

EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);

int EC_KEY_up_ref(EC_KEY *);

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);

unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);


typedef struct { 
  int nid;
  const char *comment;
  } EC_builtin_curve;

/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number 
 * of all available curves or zero if a error occurred. 
 * In case r ist not zero nitems EC_builtin_curve structures 
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

typedef unsigned int BN_ULONG;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM *BN_new(void);
void  BN_init(BIGNUM *);
void  BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void  BN_swap(BIGNUM *a, BIGNUM *b);

int     BN_cmp(const BIGNUM *a, const BIGNUM *b);
int     BN_set_word(BIGNUM *a, BN_ULONG w);

void    BN_set_negative(BIGNUM *b, int n);

int     BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int     BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

int     BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int     BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);

int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

int     BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);

int _bn_num_bytes(BIGNUM * a);
int BN_num_bits(const BIGNUM *a);
char *  BN_bn2dec(const BIGNUM *a);
char *  BN_bn2hex(const BIGNUM *a);
int     BN_hex2bn(BIGNUM **a, const char *str);
int     BN_dec2bn(BIGNUM **a, const char *str);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int     BN_bn2bin(const BIGNUM *a, unsigned char *to);

int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add, 
    const BIGNUM *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);

typedef unsigned int SHA_LONG;
#define SHA_LBLOCK ...

typedef struct SHA256state_st
        {
        SHA_LONG h[8];
        SHA_LONG Nl,Nh;
        SHA_LONG data[16];
        unsigned int num,md_len;
        } SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);

""")

_C = _FFI.verify("""
#include <openssl/ec.h>
#include <openssl/sha.h>

#define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

int _bn_num_bytes(BIGNUM * a){
  return BN_num_bytes(a);
}

""", libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations'])

# # NIST/X9.62/SECG curve over a 192 bit prime field
# curveID = 409

class BnCtx(object):
  pass

def force_Bn(n):
  def convert_nth(f):
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

      raise Exception("Cannot apply type %s", type(args[n]))
    return new_f
  return convert_nth


class Bn(object):
  # We know this class will keep minimal state
  __slots__ = ['bn']

  ## -- static methods  
  @staticmethod
  def from_decimal(sdec):
    ptr = _FFI.new("BIGNUM **")
    assert (_C.BN_dec2bn(ptr, sdec))

    ret = Bn()
    _C.BN_copy(ret.bn, ptr[0])
    _C.BN_clear_free(ptr[0])
    return ret

  @staticmethod
  def from_hex(shex):
    ptr = _FFI.new("BIGNUM **")
    assert (_C.BN_hex2bn(ptr, shex))

    ret = Bn()
    _C.BN_copy(ret.bn, ptr[0])
    _C.BN_clear_free(ptr[0])
    return ret

  @staticmethod
  def from_binary(sbin):
    ret = Bn()
    _C.BN_bin2bn(sbin, len(sbin), ret.bn)
    return ret

  @staticmethod
  def get_prime(bits, safe=1):
    assert 0 < bits < 10000
    assert safe in [0,1]
    # BN_generate_prime_ex(r, 512, 0, NULL, NULL, NULL);
    ret = Bn()
    assert _C.BN_generate_prime_ex(ret.bn, bits, safe, _FFI.NULL, _FFI.NULL, _FFI.NULL)
    return ret


  ## -- methods

  def __init__(self, num=0):
    'Allocate a big number'
    assert 0 <= abs(num) <= 2**(64-1)  
    self.bn = _C.BN_new()

    # Assign
    if num != 0:
      self._check(_C.BN_set_word(self.bn, abs(num)))

    if num < 0:
      self._set_neg(1)

  def _set_neg(self, sign=1):
    assert sign == 0 or sign == 1
    _C.BN_set_negative(self.bn, sign)

  def _check(self, return_val):
    assert return_val 

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
    assert type(other) == Bn
    sig = int(_C.BN_cmp(self.bn, other.bn))
    return sig

  def __nonzero__(self):
    'Turn into boolean' 
    return not (self == Bn(0))

  ## Export in different representations

  def __repr__(self):
    'The representation of the string in decimal'
    buf =  _C.BN_bn2dec(self.bn);
    s = str(_FFI.string(buf))
    _C.OPENSSL_free(buf)
    return s

  def __int__(self):
    return int(self.__repr__())

  def __index__(self):
    return int(self.__repr__())


  def __hex__(self):
    'The representation of the string in hexadecimal'
    buf =  _C.BN_bn2hex(self.bn);
    s = str(_FFI.string(buf))
    _C.OPENSSL_free(buf)
    return s

  def binary(self):
    size = _C._bn_num_bytes(self.bn);
    bin_string = _FFI.new("unsigned char[]", size)
    assert _C.BN_bn2bin(self.bn, bin_string);
    return str(_FFI.buffer(bin_string)[:])


  ## ---------- Arithmetic --------------

  @force_Bn(1)
  def __add__(self, other):
    r = Bn()
    self._check(_C.BN_add(r.bn, self.bn, other.bn))
    return r

  @force_Bn(1)
  def __sub__(self, other):
    r = Bn()
    self._check(_C.BN_sub(r.bn, self.bn, other.bn))
    return r

  @force_Bn(1)
  def __mul__(self, other):
    try:
      bnctx = _C.BN_CTX_new()
      r = Bn()
      self._check(_C.BN_mul(r.bn, self.bn, other.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return r

  @force_Bn(1)
  def __divmod__(self, other):
    # int     BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
    try:
      bnctx = _C.BN_CTX_new()
      dv = Bn()
      rem = Bn()
      self._check(_C.BN_div(dv.bn, rem.bn, self.bn, other.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return (dv, rem)

  @force_Bn(1)
  def __div__(self, other):
    dv, _ = divmod(self, other)
    return dv

  @force_Bn(1)
  def __mod__(self, other):
    _, m = divmod(self, other)
    return m

  @force_Bn(1)
  def __truediv__(self, other):
    return self.__div__(other)

  @force_Bn(1)
  def __floordiv__(self, other):
    return self.__div__(other)

  @force_Bn(1)
  @force_Bn(2)
  def __pow__(self, other, modulo=None):
    try:
      bnctx = _C.BN_CTX_new()
      res = Bn()
      if modulo is None:
        self._check(_C.BN_exp(res.bn, self.bn, other.bn, bnctx))
      else:
        self._check(_C.BN_mod_exp(res.bn, self.bn, other.bn, modulo.bn, bnctx))
    finally:
      _C.BN_CTX_free(bnctx)
    return res

  @force_Bn(1)
  def mod_inverse(self, m):
    'Compute the inverse mod m, such that self * res == 1 mod m.'
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
    'Returns True if the number is prime, with negligible prob. of error.'
    # int BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
    res = int(_C.BN_is_prime_ex(self.bn, 0, _FFI.NULL, _FFI.NULL))
    if res == 0:
      return False
    if res == 1:
      return True
    raise Exception("Primality test failure %s" % int(res) )

  def num_bits(self):
    return int(_C.BN_num_bits(self.bn))

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
  assert Bn.from_decimal("100") == Bn(100)
  assert Bn.from_decimal("-100") == Bn(-100)

  assert Bn.from_hex(hex(Bn(-100))) == Bn(-100)

  assert Bn.from_binary(Bn(-100).binary()) == Bn(100)
  assert Bn.from_binary(Bn(100).binary()) == Bn(100)
  assert Bn.from_binary(Bn(100).binary()) == Bn(100)
  assert Bn.from_binary(Bn(-100).binary()) != Bn(50)
  assert int(Bn(-100)) == -100

def test_prime():
  p = Bn.get_prime(512)
  assert p > Bn(0)
  assert p.is_prime()
  assert not Bn(16).is_prime()
  assert p.num_bits() > 500

def test_bn_arithmetic():
  assert (Bn(1) + Bn(1) == Bn(2))
  assert (Bn(1) + 1 == Bn(2))
  # assert (1 + Bn(1) == Bn(2))
  
  assert (Bn(1) + Bn(-1) == Bn(0))
  assert (Bn(10) + Bn(10) == Bn(20))
  assert (Bn(-1) * Bn(-1) == Bn(1))

  assert (Bn(10) * Bn(10) == Bn(100))
  assert (Bn(10) - Bn(10) == Bn(0))
  assert (Bn(10) - Bn(100) == Bn(-90))
  assert (Bn(10) + (-Bn(10)) == Bn(0))
  s = -Bn(100)
  assert (Bn(10) + s == Bn(-90))
  assert (Bn(10) - (-Bn(10)) == Bn(20))

  assert divmod(Bn(10), Bn(3)) == (Bn(3), Bn(1))
  assert Bn(10) // Bn(3) == Bn(3)
  assert Bn(10) % Bn(3) == Bn(1)
  
  assert Bn(2) ** Bn(8) == Bn(2 ** 8)
  assert pow(Bn(2), Bn(8), Bn(27)) == Bn(2 ** 8 % 27)

  assert pow(Bn(2), 8, 27) == 2 ** 8 % 27

  assert Bn(3).mod_inverse(Bn(16)) == Bn(11)

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

class EcGroup(object):
  pass

class EcPoint(object):
  pass
