from array import array
from struct import pack
from hashlib import sha512
from copy import copy

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

# Make a cached decryption table
def _make_table(start=-10000, end=10000):
    G = EcGroup()
    g = G.generator()
    o = G.order()

    i_table = {}
    n_table = {}
    ix = start * g
    for i in range(start, end):
        i_table[ix] = i
        n_table[(o + i) % o] = ix
        ix = ix + g
        
    return i_table, n_table

_table, _n_table = _make_table()

class Ct:

    @staticmethod
    def enc(pub, m):
        """ Produce a ciphertext, from a public key and message """
        if isinstance(m, int):
            m = Bn(m)

        o = pub.group.order()
        k = o.random()
        g = pub.group.generator()
        a = k * g
        b = k * pub + _n_table[(o + m) % o] # m * g
        return Ct(pub, a, b, k, m) 

    def __init__(self, pub, a, b, k=None, m=None):
        """ Produce a ciphertext, from its parts """
        self.pub = pub
        self.a = a
        self.b = b
        self.k = k
        self.m = m

        if __debug__:
            self.self_check()

    def self_check(self):
        """ Runs a self check """
        if self.k is not None and self.m is not None:
            g = self.pub.group.generator()
            assert self.a == self.k * g
            assert self.b == self.k * self.pub + self.m * g

    def dec(self, x):
        """ Decrypt a ciphertext using a secret key """
        try:
            hm = self.b - x * self.a
            return _table[hm]
        except Exception as e:
            o = self.pub.group.order()
            self.self_check()
            print("Failed to decrypt: %s" % self.m )
            raise e

    def __add__(self, other):
        """ Add two ciphertexts, to produce a ciphertext of their sums. Also handles addition with a constant. """
        o = self.pub.group.order()
        g = self.pub.group.generator()

        if isinstance(other, int):
            # Case for int other
            new_b = self.b + _n_table[(o + other) % o] # other * g
            new_k, new_m = None, None
            if self.k is not None:
                new_m = self.m + other # self.m.mod_add( other, o)
            return Ct(self.pub, self.a, new_b, self.k, new_m)
        else:
            # Case for ciphertext other
            if __debug__:
                assert self.pub == other.pub
            new_a = self.a + other.a
            new_b = self.b + other.b
            new_k, new_m = None, None
            if self.k is not None and other.k is not None:
                new_k = self.k.mod_add( other.k, o)
                new_m = self.m + other.m # self.m.mod_add(other.m, o)
            return Ct(self.pub, new_a, new_b, new_k, new_m)

    @staticmethod
    def sum(elist):
        """ Sums a number of Cts """
        pub = elist[0].pub
        G = pub.group
        # w = [Bn(1) for _ in range(len(elist))]
        as_l = [e.a for e in elist]
        bs_l = [e.b for e in elist]

        new_a = G.sum(as_l)
        new_b = G.sum(bs_l)

        return Ct(pub, new_a, new_b)

    def __rmul__(self, other):
        """ Multiples an integer with a Ciphertext """
        o = self.pub.group.order()
        new_a = other * self.a 
        new_b = other * self.b
        new_k, new_m = None, None
        if self.k is not None:
            new_k = self.k.mod_mul( other, o)
            new_m = self.m.mod_mul( other, o) 
        return Ct(self.pub, new_a, new_b, new_k, new_m)

    def __neg__(self):
        """ Multiply the value by -1 """
        o = self.pub.group.order()
        new_a = -self.a 
        new_b = -self.b
        if self.k is not None and self.m is not None:
            new_k = (o - self.k) % o
            new_m = - self.m
        else:
            new_k = None
            new_m = None

        return Ct(self.pub, new_a, new_b, new_k, new_m)

    def rnd(self):
        """ Re-randomize a ciphertext """
        E0 = Ct.enc(self.pub, 0)
        return self + E0


def hashes(item, d):
    """ Returns d hashes / positions for the item """
    codes = []
    i = 0
    while len(codes) < d:
        codes += list(array('I', sha512(pack("I", i) + item.encode("utf8")).digest())) 
        i += 1
    return codes[:d]


class CountSketchCt(object):
    """ A Count Sketch of Encrypted values """

    def __init__(self, w, d, pub):
        """ Initialize a w * d Count Sketch under a public key """

        if __debug__:
            assert isinstance(w, int) and w > 0
            assert isinstance(d, int) and d > 0

        self.pub = pub
        self.d, self.w = d, w
        self.store = [ [Ct.enc(pub, 0)] * w for _ in range(d) ]

    def insert(self, item):
        """ Insert an element into the encrypted count sketch """

        item = str(item)
        h = hashes(item, self.d)
        for di in range(self.d):
            self.store[di][h[di] % self.w] += 1 

    def estimate(self, item):
        """ Estimate the frequency of one value """

        item = str(item)
        h = hashes(item, self.d)
        h2 = []
        for hi in h:
            v = hi - 1 if hi % 2 == 0 else hi + 1
            h2 += [v]

        g = self.pub.group.generator()
        o = self.pub.group.order()

        elist = []
        for i, [hi, hpi] in enumerate(zip(h, h2)):
            v1 = self.store[i][hi % self.w] 
            v2 = self.store[i][hpi % self.w]
            elist += [v1, -v2]
        
        estimates = Ct.sum(elist)
        return estimates, self.d

    @staticmethod
    def aggregate(others):
        o0 = others[0]
        pub, w, d = o0.pub, o0.w, o0.d

        if __debug__:
            for o in others:
                assert pub == o.pub
                assert w == o.w and d == o.d
        
        cs = CountSketchCt(w, d, pub)

        for di in range(d):
            for wi in range(w):
                elist = []
                for o in others:
                    elist += [o.store[di][wi]]
                cs.store[di][wi] = Ct.sum(elist)

        return cs

#### ------------- TESTS ------------------

from random import gauss

def test_Ct():
    assert True
    G = EcGroup()
    x = G.order().random()
    y = x * G.generator()
    E1 = Ct.enc(y, 2)
    E2 = Ct.enc(y, 2)
    assert (E1 + E2).dec(x) == 4
    assert (E1 + E2).m == 4
    assert (E1 + 3).dec(x) == 5
    assert (3 * E2).dec(x) == 6
    assert (3 * E2).m == 6
    assert (3 * E2).rnd().dec(x) == 6

    E10 = Ct.enc(y, 11)
    E20 = Ct.enc(y, 22)
    assert (E20 + (-E10)).dec(x) == 11
    assert (E10 + (-E20)).dec(x) == -11

    assert Ct.enc(y, -64).dec(x) == -64

    assert Ct.sum([ Ct.enc(y, 2) ] * 10).dec(x) == 20


def test_Decrypt():
    G = EcGroup()
    x = G.order().random()
    y = x * G.generator()
    import random

    for _ in range(100):
        i = random.randint(-1000, 999)
        E = Ct.enc(y, i)
        assert E.dec(x) == i
    

def test_CountSketchCt():
    G = EcGroup()
    x = G.order().random()
    y = x * G.generator()
    
    cs = CountSketchCt(50, 7, y)
    cs.insert(11)
    c, d = cs.estimate(11)
    est = c.dec(x)
    # print(est)
    assert est == d


def test_median():

    import time

    # Get some test data
    vals = [gauss(300, 25) for _ in range (1000)]
    vals += [gauss(300, 200) for _ in range (200)]
    vals = sorted([int(v) for v in vals])

    median = vals[int(len(vals) / 2)]
    print("Correct sample median: %s" % median)

    # Setup the crypto
    G = EcGroup()
    sec = G.order().random()
    y = sec * G.generator()
    
    # Add each sample to the sketch
    tic = time.clock()    

    all_cs = []
    for x in vals:
        cs_temp = CountSketchCt(50, 7, y)
        cs_temp.insert("%s" % x)
        all_cs += [ cs_temp ]

    toc = time.clock()
    print("Build Sketches: %s" % (toc - tic) )

    # Aggregate all sketches
    tic = time.clock()
    cs = CountSketchCt.aggregate(all_cs)

    toc = time.clock()
    print("Aggregate Sketches: %s" % (toc - tic) )

    # Implement a divide and conquer algo. for median
    L, R = 0, 0
    bounds = [0, 1000]
    total = None

    for _ in range(20):
        old_bounds = copy(bounds)
        # print(bounds)

        tic = time.clock()
        cand_median = int((bounds[1] + bounds[0]) / 2)

        if bounds[0] == cand_median:
            break

        EL = Ct.sum([ cs.estimate(i)[0] for i in range(bounds[0], cand_median) ])
        newl = EL.dec(sec)
        
        if total is None:
            ER = Ct.sum([ cs.estimate(i)[0] for i in range(cand_median, bounds[1]) ])        
            newr = ER.dec(sec)

            total = newl + newr
            # print("total: %s" % total)

        else:
            newr = total - newl
            if __debug__:
                ER = Ct.sum( [ cs.estimate(i)[0] for i in range(cand_median, bounds[1]) ])        
                newrx = ER.dec(sec)
                assert newrx == newr

        if newl + L > newr + R:
            R = R + newr
            bounds[1] = cand_median
            total = newl
        else:
            L = L + newl
            bounds[0] = cand_median
            total = newr

        toc = time.clock()
        print( "Pivot: % 5d\tEL: % 5d\tER: % 5d\ttime: %2.4f" % (cand_median, newl + L, newr + R, toc - tic) )
        # print( "Timing: %s" % (toc - tic))

        if bounds == old_bounds:
            break

    print("Estimated median: %s" % cand_median)

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description='Test and time the Tor median statistics.')
    parser.add_argument('--time', action='store_true', help='Run timing tests')
    parser.add_argument('--lprof', action='store_true', help='Run the line profiler')
    parser.add_argument('--cprof', action='store_true', help='Run the c profiler')

    args = parser.parse_args()

    if args.time:
        test_median()

    if args.cprof:
        import cProfile    
        cProfile.run("test_median()", sort="tottime")
        # test_median()

    if args.lprof:
        from line_profiler import LineProfiler

        profile = LineProfiler(test_median, CountSketchCt.estimate, CountSketchCt.aggregate,
            Ct.__add__, EcPt.__add__, EcPt.__neg__, EcPt.__copy__,)
        profile.run("test_median()")
        profile.print_stats()