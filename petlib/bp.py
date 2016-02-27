from .bindings import _FFI, _C, Const
from .bn import Bn, force_Bn, _ctx

from copy import copy
from binascii import hexlify
from hashlib import sha512

try:
    from builtins import int        # pylint: disable=redefined-builtin
    from builtins import object     # pylint: disable=redefined-builtin
except:                             # pylint: disable=bare-except
    print('Cannot mock for docs')

try:
    from future.utils import python_2_unicode_compatible
except Exception as e:              # pylint: disable=broad-except
    # An identity decorator
    python_2_unicode_compatible = lambda x: x

def _check(return_val):
        """Checks the return code of the C calls"""
        if __debug__:
            if isinstance(return_val, int) and return_val == 1:
                return
            if isinstance(return_val, bool) and return_val == True:
                return

        if return_val == 1 or return_val == True:
            return

        raise Exception("EC exception: %s" % return_val) 


import pytest

NID_fp254bnb = 1

class BpGroup(object):
    
    def __init__(self, nid=NID_fp254bnb, optimize_mult=True):
        """Build an BP group from the Open SSL nid."""

        self.nid = nid

        self.bpg = _C.BP_GROUP_new_by_curve_name(nid)
        self.optimize_mult = optimize_mult

        if optimize_mult:
            _check(_C.BP_GROUP_precompute_mult_G1(self.bpg, _FFI.NULL))
            _check(_C.BP_GROUP_precompute_mult_G2(self.bpg, _FFI.NULL))

        self.g1 = G1Elem(self)
        _check( _C.BP_GROUP_get_generator_G1(self.bpg, self.g1.elem) )

        self.g2 = G2Elem(self)
        _check( _C.BP_GROUP_get_generator_G2(self.bpg, self.g2.elem) )

        self.ord = None
        self.inf = None

    def order(self):
        """Returns the order of the group as a Big Number.

        Example:
            >>> G = BpGroup()
            >>> print(G.order())
            16798108731015832284940804142231733909759579603404752749028378864165570215949

        """

        if self.ord is None:
            o = Bn()
            _check( _C.BP_GROUP_get_order(self.bpg, o.bn, _FFI.NULL) )
            self.ord = o

        return self.ord

    def gen1(self):
        """ Returns the generator for G1. """
        return self.g1

    def gen2(self):
        """ Returns the generator for G2. """
        return self.g2

    def pair(self, g1, g2):
        """ The pairing operation e(G1, G2) -> GT. 

            Example:
                >>> G = BpGroup()
                >>> g1, g2 = G.gen1(), G.gen2()
                >>> gt = G.pair(g1, g2)
                >>> gt6 = G.pair(g1.mul(2), g2.mul(3))
                >>> gt.exp(6).eq( gt6 )
                True

        """

        gt = GTElem(self)
        _check( _C.GT_ELEM_pairing(self.bpg, gt.elem, g1.elem, g2.elem, _FFI.NULL) )
        return gt


    def __copy__(self):
        return BpGroup(self.nid, self.optimize_mult)

    def __del__(self):
        """ Clears the Group object """
        if self.bpq is not None:
            _C.BP_GROUP_clear_free(self.bpg)

class G1Elem:

    @staticmethod
    def inf(group):
        """ Returns the element at infinity for G1 """
        zero = G1Elem(self.group)
        _check( _C.G1_ELEM_set_to_infinity(group.bpg, zero.elem) )
        return zero

    def __init__(self, group):
        """ Returns and element of G1 """
        self.group = group
        self.elem = _C.G1_ELEM_new(group.bpg);

    def __copy__(self):
        """ Copy the G1 point. """
        newpt = G1Elem(self.group)
        _check( _C.G1_ELEM_copy(newpt.elem, self.elem) )
        return newpt

    def add(self, other):
        """ Returns the sum of two points. """
        newpt = G1Elem(self.group)
        _check( _C.G1_ELEM_add(self.group.bpg, newpt.elem, self.elem, other.elem, _FFI.NULL) )
        return newpt   

    def double(self):
        """ Returns the double of the G1 point. """
        newpt = G1Elem(self.group)
        _check( _C.G1_ELEM_dbl(self.group.bpg, newpt.elem, self.elem, _FFI.NULL) )
        return newpt

    def inv(self):
        """ Returns the inverse point. 

            Example:
                >>> g1 = BpGroup().gen1()
                >>> g1.add(g1.inv()).isinf()
                True

        """
        newpt = self.__copy__()
        _check( _C.G1_ELEM_invert(self.group.bpg, newpt.elem, _FFI.NULL))
        return newpt

    def eq(self, other):
        """ Returns True if points are equal.

            Example:
                >>> G = BpGroup()
                >>> g1 = G.gen1()
                >>> g1.add(g1).eq(g1.double())
                True
                >>> g1.eq(g1.double())
                False
        """
        resp = _C.G1_ELEM_cmp(self.group.bpg, self.elem, other.elem, _FFI.NULL)
        return (int(resp) == 0)

    def isinf(self):
        return int(_C.G1_ELEM_is_at_infinity(self.group.bpg, self.elem)) == 1

    @force_Bn(1)
    def mul(self, scalar):
        """ Multiplies the point with a scalar. 

            Example:
                >>> g1 = BpGroup().gen1()
                >>> g1.mul(2).eq(g1.double())
                True

        """
        newpt = G1Elem(self.group)
        _check( _C.G1_ELEM_mul(self.group.bpg, newpt.elem, _FFI.NULL, self.elem, scalar.bn, _FFI.NULL) )
        return newpt

    def export(self, form=_C.POINT_CONVERSION_COMPRESSED):
        """ Export a point to a byte representation. """
        size = int(_C.G1_ELEM_point2oct(self.group.bpg, self.elem, form, _FFI.NULL, 0, _FFI.NULL))

        out = _FFI.new("unsigned char[]", size)
        _C.G1_ELEM_point2oct(self.group.bpg, self.elem, form, out, size, _FFI.NULL)
        ret = bytes(_FFI.buffer(out)[:size])

        return ret

    @staticmethod
    def from_bytes(sbin, group):
        """ Import a G1 point from bytes.

            Export:
                >>> G = BpGroup()
                >>> g1 = G.gen1()
                >>> buf = g1.export()
                >>> g1p = G1Elem.from_bytes(buf, G)
                >>> g1.eq(g1p)
                True

        """
        pt_bytes = _FFI.new("unsigned char[]", sbin)

        newpt = G1Elem(group)
        _check( _C.G1_ELEM_oct2point(group.bpg, newpt.elem, pt_bytes, len(sbin), _FFI.NULL) )

        return newpt

    def __del__(self):
        _C.G1_ELEM_clear_free(self.elem);


class G2Elem:

    @staticmethod
    def inf(group):
        """ Returns the element at infinity for G2. """
        zero = G2Elem(self.group)
        _check( _C.G2_ELEM_set_to_infinity(group.bpg, zero.elem) )
        return zero

    def __init__(self, group):
        """ Returns and element of G2. """
        self.group = group
        self.elem = _C.G2_ELEM_new(group.bpg);

    def __copy__(self):
        """ Copy the G2 point. """
        newpt = G2Elem(self.group)
        _check( _C.G2_ELEM_copy(newpt.elem, self.elem) )
        return newpt

    def add(self, other):
        """ Returns the sum of two points. """
        newpt = G2Elem(self.group)
        _check( _C.G2_ELEM_add(self.group.bpg, newpt.elem, self.elem, other.elem, _FFI.NULL) )
        return newpt   

    def double(self):
        """ Returns the double of the G2 point. """
        newpt = G2Elem(self.group)
        _check( _C.G2_ELEM_dbl(self.group.bpg, newpt.elem, self.elem, _FFI.NULL) )
        return newpt

    def inv(self):
        """ Returns the inverse point. 

            Example:
                >>> g2 = BpGroup().gen2()
                >>> g2.add(g2.inv()).isinf()
                True

        """
        newpt = self.__copy__()
        _check( _C.G2_ELEM_invert(self.group.bpg, newpt.elem, _FFI.NULL))
        return newpt

    def eq(self, other):
        """ Returns True if points are equal.

            Example:
                >>> G = BpGroup()
                >>> g2 = G.gen2()
                >>> g2.add(g2).eq(g2.double())
                True
                >>> g2.eq(g2.double())
                False
        """
        resp = _C.G2_ELEM_cmp(self.group.bpg, self.elem, other.elem, _FFI.NULL)
        return (int(resp) == 0)

    def isinf(self):
        return int(_C.G2_ELEM_is_at_infinity(self.group.bpg, self.elem)) == 1

    @force_Bn(1)
    def mul(self, scalar):
        """ Multiplies the point with a scalar. 

            Example:
                >>> g2 = BpGroup().gen2()
                >>> g2.mul(2).eq(g2.double())
                True

        """
        newpt = G2Elem(self.group)
        _check( _C.G2_ELEM_mul(self.group.bpg, newpt.elem, _FFI.NULL, self.elem, scalar.bn, _FFI.NULL) )
        return newpt

    def export(self, form=_C.POINT_CONVERSION_UNCOMPRESSED):
        """ Export a point to a byte representation. """
        size = int(_C.G2_ELEM_point2oct(self.group.bpg, self.elem, form, _FFI.NULL, 0, _FFI.NULL))
        
        out = _FFI.new("unsigned char[]", size)
        _C.G2_ELEM_point2oct(self.group.bpg, self.elem, form, out, size, _FFI.NULL)
        ret = bytes(_FFI.buffer(out)[:size])

        return ret

    @staticmethod
    def from_bytes(sbin, group):
        """ Import a G2 point from bytes.

            Export:
                >>> G = BpGroup()
                >>> g2 = G.gen2()
                >>> buf = g2.export()
                >>> g2p = G2Elem.from_bytes(buf, G)
                >>> g2.eq(g2p)
                True

        """
        pt_bytes = _FFI.new("unsigned char[]", sbin)

        newpt = G2Elem(group)
        _check( _C.G2_ELEM_oct2point(group.bpg, newpt.elem, pt_bytes, len(sbin), _FFI.NULL) )

        return newpt

class GTElem:

    @staticmethod
    def zero(group):
        """ Returns the element at infinity for G2. """
        zero_pt = GTElem(group)
        _check( _C.GT_ELEM_zero(zero_pt.elem) )
        return zero_pt

    def iszero(self):
        return int(_C.GT_ELEM_is_zero(self.elem)) == 1

    @staticmethod
    def one(group):
        """ Returns the element at infinity for G2. """
        one_pt = GTElem(group)
        _check( _C.GT_ELEM_set_to_unity(group.bpg, one_pt.elem) )
        return one_pt

    def isone(self):
        return int(_C.GT_ELEM_is_unity(self.group.bpg, self.elem)) == 1

    def __init__(self, group):
        """ Returns and element of G2. """
        self.group = group
        self.elem = _C.GT_ELEM_new(group.bpg);

    def __copy__(self):
        """ Copy the G2 point. 

        Example:
            >>> G = BpGroup()
            >>> g1, g2 = G.gen1(), G.gen2()
            >>> gt = G.pair(g1, g2)
            >>> gtp = gt.__copy__()
            >>> gt.eq(gtp)
            True

        """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_copy(newpt.elem, self.elem) )
        return newpt

    def add(self, other):
        """ Returns the sum of two points. 

            Example:
                >>> G = BpGroup()
                >>> zero = GTElem.zero(G)
                >>> x = zero.add(zero)
                >>> x.iszero()
                True
        """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_add(self.group.bpg, newpt.elem, self.elem, other.elem, _FFI.NULL) )
        return newpt

    def sub(self, other):
        """ Returns the sum of two points. 

            Example:
                >>> G = BpGroup()
                >>> one = GTElem.one(G)
                >>> x = one.sub(one)
                >>> x.iszero()
                True
        """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_sub(self.group.bpg, newpt.elem, self.elem, other.elem, _FFI.NULL) )
        return newpt

    def mul(self, other):
        """ Returns the sum of two points. 

            Example:
                >>> G = BpGroup()
                >>> gt = G.pair(G.gen1(), G.gen2())
                >>> gtinv = gt.inv()
                >>> x = gt.mul(gtinv)
                >>> x.isone()
                True
        """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_mul(self.group.bpg, newpt.elem, self.elem, other.elem, _FFI.NULL) )
        return newpt


    # def double(self):
    #     """ Returns the double of the G2 point. """
    #     newpt = G2Elem(self.group)
    #     _check( _C.G2_ELEM_dbl(self.group.bpg, newpt.elem, self.elem, _FFI.NULL) )
    #     return newpt

    def inv(self):
        """ Returns the inverse point. 

            Example:
                >>> G = BpGroup()
                >>> gt = G.pair(G.gen1(), G.gen2())
                >>> gt2 = gt.mul(gt)
                >>> gtp = gt.sqr()
                >>> gtp.eq(gt2)
                True

        """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_inv(self.group.bpg, newpt.elem, self.elem, _FFI.NULL))
        return newpt

    def sqr(self):
        """ Returns the square of a point. """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_sqr(self.group.bpg, newpt.elem, self.elem, _FFI.NULL))
        return newpt


    def eq(self, other):
        """ Returns True if points are equal. """
        resp = _C.GT_ELEM_cmp(self.elem, other.elem)
        return (int(resp) == 0)

    @force_Bn(1)
    def exp(self, scalar):
        """ Exponentiates the point with a scalar. """
        newpt = GTElem(self.group)
        _check( _C.GT_ELEM_exp(self.group.bpg, newpt.elem, self.elem, scalar.bn, _FFI.NULL) )
        return newpt

    def export(self):
        """ Export a point to a byte representation. """
        size = int(_C.GT_ELEM_elem2oct(self.group.bpg, self.elem, _FFI.NULL, 0, _FFI.NULL))
        
        out = _FFI.new("unsigned char[]", size)
        _C.GT_ELEM_elem2oct(self.group.bpg, self.elem, out, size, _FFI.NULL)
        ret = bytes(_FFI.buffer(out)[:size])

        return ret

    @staticmethod
    def from_bytes(sbin, group):
        """ Import a GT point from bytes.

            Export:
                >>> G = BpGroup()
                >>> gt = G.pair(G.gen1(), G.gen2())
                >>> buf = gt.export()
                >>> gtp = GTElem.from_bytes(buf, G)
                >>> gt.eq(gtp)
                True

        """
        pt_bytes = _FFI.new("unsigned char[]", sbin)

        newpt = GTElem(group)
        _check( _C.GT_ELEM_oct2elem(group.bpg, newpt.elem, pt_bytes, len(sbin), _FFI.NULL) )

        return newpt
    