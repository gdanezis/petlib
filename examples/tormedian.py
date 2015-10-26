from array import array
from struct import pack
from hashlib import sha512
from copy import copy
import time

import math

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

    @staticmethod
    def epsilondelta(epsilon, delta, pub):
        w = int(math.ceil(math.e / epsilon))
        d = int(math.ceil(math.log(1.0 / delta)))
        return CountSketchCt(w, d, pub)

    def __init__(self, w, d, pub):
        """ Initialize a w * d Count Sketch under a public key """

        if __debug__:
            assert isinstance(w, int) and w > 0
            assert isinstance(d, int) and d > 0

        self.pub = pub
        self.d, self.w = d, w
        self.store = [ [Ct.enc(pub, 0) for i in range(w)] for j in range(d) ]

        # zero = Ct.enc(pub, 0)
        #self.store = [ [zero for i in range(w)] for j in range(d) ]

    def dump(self):
        from cStringIO import StringIO
        from struct import pack

        dst = StringIO()
        dst.write(pack("II", self.d, self.w))

        for di in range(self.d):
            for wi in range(self.w):
                ba = self.store[di][wi].a.export()
                dst.write(pack("I", len(ba)))
                dst.write(ba)
                
                bb = self.store[di][wi].b.export()
                dst.write(pack("I", len(bb)))
                dst.write(bb)

        return dst.getvalue()
                


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


def get_median(cs, min_b = 0, max_b = 1000, steps = 20):
    L, R = 0, 0
    bounds = [min_b, max_b]
    total = None

    for _ in range(steps):
        old_bounds = copy(bounds)
        # print(bounds)

        cand_median = int((bounds[1] + bounds[0]) / 2)

        if bounds[0] == cand_median:
            yield cand_median
            return

        EL = Ct.sum([ cs.estimate(i)[0] for i in range(bounds[0], cand_median) ])
        newl = yield EL # EL.dec(sec)
        
        if total is None:
            ER = Ct.sum([ cs.estimate(i)[0] for i in range(cand_median, bounds[1]) ])        
            newr = yield ER # ER.dec(sec)

            total = newl + newr
            # print("total: %s" % total)

        else:
            newr = total - newl
            if __debug__:
                ER = Ct.sum( [ cs.estimate(i)[0] for i in range(cand_median, bounds[1]) ])        
                newrx = yield ER # ER.dec(sec)
                # assert newrx == newr

        if newl + L > newr + R:
            R = R + newr
            bounds[1] = cand_median
            total = newl
        else:
            L = L + newl
            bounds[0] = cand_median
            total = newr

        if bounds == old_bounds:
            yield cand_median
            return 


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
    


def analyze_series(eps, datapoints):
    import matplotlib.pyplot as plt
    from numpy import mean, std

    upper_err = []
    core_err = []
    lower_err = []

    for e in eps:
        samples = sorted(datapoints[e])
        core_err.append(mean(samples))
        upper_err.append(mean(samples) + std(samples) / (len(samples)**0.5))
        lower_err.append(mean(samples) - std(samples) / (len(samples)**0.5))

    return lower_err, core_err, upper_err


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


def size_vs_error():
    #d, w = 25, 7
    #print("Sketch: d=%s w=%s (Cmp. size: %s%%)" % (d, w, (float(100*d*w)/1000)))

    # Setup the crypto
    G = EcGroup()
    sec = G.order().random()
    y = sec * G.generator()

    # Get some test data
    narrow_vals = 1000
    wide_vals = 200

    from numpy.random import laplace    
    from collections import defaultdict

    
    datapoints = defaultdict(list)
    sizes = defaultdict(list)

    eps = [0.5, 0.35, 0.25, 0.15, 0.1, 0.05, 0.025, 0.01]  #, 0.005, 0.001]
    for epsilon in eps:
        print epsilon

        for _ in range(40):
            vals = [gauss(300, 25) for _ in range (narrow_vals)]
            vals += [gauss(500, 200) for _ in range (wide_vals)]
            vals = sorted([int(v) for v in vals])

            median = vals[int(len(vals) / 2)]

            # Add each sample to the sketch
            # cs = CountSketchCt(d, w, y)
            cs = CountSketchCt.epsilondelta(epsilon, epsilon, y)
            sizes[epsilon] += [ float(100*cs.d*cs.w) / 1000 ]
            for x in vals:
                cs.insert("%s" % x)

            # Now use test the median function
            proto = get_median(cs, min_b = 0, max_b = 1000, steps = 20)

            plain = None
            no_decryptions = 0
            while True:
                v = proto.send(plain)
                if isinstance(v, int):
                    break
                no_decryptions += 1

                noise = 0
                plain = v.dec(sec) + noise

            print("Estimated median: %s\t\tAbs. Err: %s" % (v, abs(v - median)))
            datapoints[epsilon] += [ 100 * float(abs(v - median)) / median ] 

    lower_err, core_err, upper_err = analyze_series(eps, datapoints)
    lower_siz, core_siz, upper_siz = analyze_series(eps, sizes)

    import matplotlib.pyplot as plt

    eps_lab = range(len(eps))


    plt.plot(eps, core_err, label="Error (%)")
    plt.xscale('log')
    # v = v_issue / (len(cnt_issue)**0.5)
    plt.fill_between(x=eps, y1=lower_err, y2=upper_err, alpha=0.2, color="b")
    plt.xticks(eps, eps)


    plt.plot(eps, core_siz, label=r"Size (%)")
    # plt.yscale('log')
    # v = v_issue / (len(cnt_issue)**0.5)
    plt.fill_between(x=eps, y1=lower_siz, y2=upper_siz, alpha=0.2, color="b")
    # plt.xticks(eps_lab, eps)

    plt.xlabel(r'(epsilon, delta) parameter of Count-Sketch')
    plt.ylabel(r'%')
    plt.title(r'Median Estimation - Error vs. Size')
    # plt.axis([1, 10, 0, 1700])
    #plt.grid(True)
    plt.legend(loc="upper center")

    plt.savefig("Size.pdf")

    # plt.show()
    plt.close()
    # print core_err


def no_test_DP_median():
    d, w = 25, 7
    print("Sketch: d=%s w=%s (Cmp. size: %s%%)" % (d, w, (float(100*d*w)/1000)))

    # Setup the crypto
    G = EcGroup()
    sec = G.order().random()
    y = sec * G.generator()

    # Get some test data
    narrow_vals = 1000
    wide_vals = 200

    from numpy.random import laplace    
    from collections import defaultdict

    
    datapoints = defaultdict(list)

    eps = ["Inf", 1, 0.5, 0.1, 0.05, 0.01, 0.005, 0.001]
    for epsilon in eps:
        print epsilon

        for _ in range(40):
            vals = [gauss(300, 25) for _ in range (narrow_vals)]
            vals += [gauss(500, 200) for _ in range (wide_vals)]
            vals = sorted([int(v) for v in vals])

            median = vals[int(len(vals) / 2)]

            # Add each sample to the sketch
            cs = CountSketchCt.epsilondelta(0.05, 0.05, y) # CountSketchCt(d, w, y)
            for x in vals:
                cs.insert("%s" % x)

            # Now use test the median function
            proto = get_median(cs, min_b = 0, max_b = 1000, steps = 20)

            plain = None
            no_decryptions = 0
            while True:
                v = proto.send(plain)
                if isinstance(v, int):
                    break
                no_decryptions += 1

                noise = 0
                if isinstance(epsilon, float):
                    scale = float(d) / epsilon
                    noise = int(round(laplace(0, scale)))

                plain = v.dec(sec) + noise

            print("Estimated median: %s\t\tAbs. Err: %s" % (v, abs(v - median)))
            datapoints[epsilon] += [ abs(v - median) ] 

    import matplotlib.pyplot as plt
    from numpy import mean, std

    upper_err = []
    core_err = []
    lower_err = []

    for e in eps:
        samples = sorted(datapoints[e])
        core_err.append(mean(samples))
        upper_err.append(mean(samples) + std(samples) / (len(samples)**0.5))
        lower_err.append(mean(samples) - std(samples) / (len(samples)**0.5))


    eps_lab = range(len(eps))

    eps = ["Inf"] + [e * 10 for e in eps][1:]

    plt.plot(eps_lab, core_err, label="Absolute Error")
    plt.yscale('log')
    # v = v_issue / (len(cnt_issue)**0.5)
    plt.fill_between(x=eps_lab, y1=lower_err, y2=upper_err, alpha=0.2, color="b")
    plt.xticks(eps_lab, eps)

    plt.xlabel(r'Differential Privacy parameter (epsilon)')
    plt.ylabel('Absolute Error (mean & std. of mean)')
    plt.title(r'Median Estimation - Quality vs. Protection')
    # plt.axis([1, 10, 0, 1700])
    # plt.grid(True)

    plt.savefig("Quality.pdf")

    # plt.show()
    plt.close()
    # print core_err


def do_median(vals, err=0.05, vrange=[0, 1000], verbose=True):

    # Get some test data
    vals = sorted([int(v) for v in vals])

    median = vals[int(len(vals) / 2)]
    if verbose:
        print("Correct sample median: %s (No. items: %s)" % (median, len(vals)))

    # Setup the crypto
    G = EcGroup()
    sec = G.order().random()
    y = sec * G.generator()
    

    xx = CountSketchCt.epsilondelta(err, err, y)
    d, w = xx.d, xx.w
    if verbose:
        print("Sketch: d=%s w=%s (Cmp. size: %s%%)" % (d, w, (float(100*d*w)/(vrange[1] - vrange[0]))))

    # Add each sample to the sketch
    tic = time.clock()    

    all_cs = []
    for x in vals:
        cs_temp = CountSketchCt.epsilondelta(err, err, y) # CountSketchCt(d, w, y)
        cs_temp.insert("%s" % x)
        all_cs += [ cs_temp ]

    toc = time.clock()
    if verbose:
        print("Build Sketches: %2.4f sec (for %s)\tPer Sketch: %2.4f sec" % ((toc - tic), len(vals), (toc - tic) / len(vals)) )

    # Aggregate all sketches
    tic = time.clock()
    cs = CountSketchCt.aggregate(all_cs)

    toc = time.clock()
    dt = (toc - tic)
    if verbose:
        print("Aggregate Sketches: %2.4f sec (for %s)\tPer Sketch: %2.4f sec" % (dt, len(vals), dt / len(vals)) )

    # Now use test the median function
    proto = get_median(cs, min_b = vrange[0], max_b = vrange[1], steps = 20)

    tic = time.clock()

    plain = None
    no_decryptions = 0
    while True:
        v = proto.send(plain)
        if isinstance(v, int):
            break
        no_decryptions += 1
        plain = v.dec(sec)

    toc = time.clock()
    if verbose:
        print( "Find Median. Pivot: % 5d\tNo. Decryptions: %s\ttime: %2.4f sec" % (v, no_decryptions, toc - tic) )

    # Measure the size of the sketch
    bin_cs = cs.dump()
    if verbose:
        print("Sketch size: %s bytes" % len(bin_cs))    
        print("Estimated median: %s\t\tAbs. Err: %s" % (v, abs(v - median)))
    return v


def test_median():

    # Get some test data
    narrow_vals = 100
    wide_vals = 20
    
    vals = [gauss(300, 25) for _ in range (narrow_vals)]
    vals += [gauss(500, 200) for _ in range (wide_vals)]

    do_median(vals, err=0.05)


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description='Test and time the Tor median statistics.')
    parser.add_argument('--time', action='store_true', help='Run timing tests')
    parser.add_argument('--quality', action='store_true', help='Run DP quality tests')
    parser.add_argument('--size', action='store_true', help='Run size tests')
    parser.add_argument('--lprof', action='store_true', help='Run the line profiler')
    parser.add_argument('--cprof', action='store_true', help='Run the c profiler')
    parser.add_argument('--data', action='store_true', help='Analysis on csv data')

    args = parser.parse_args()

    if args.data:
        # Read the csv file
        # Data currated from http://data.london.gov.uk/dataset/ward-profiles-and-atlas
        # Under UK Open Government Licence (http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)
        import pandas as pd
        data = pd.read_csv('LondonData.csv' , thousands=",")
        # print data.shape


        num = -1
        d = []
        for i in range(3, data.shape[1]):
            try:
                vals = sorted([float(f) for f in data.iloc[0:num, i]])
                med_gt = vals[len(vals)/2]
                
                MX = 100
                vmin = min(vals) - 10
                vmax = max(vals) + 10
                xvals = [MX * (v - vmin) / (vmax - vmin) for v in vals]

                xmed = do_median(xvals, err=0.25, vrange=[0, MX], verbose=True)
                med1 = xmed * (vmax - vmin) / MX + vmin
                err1 = abs(med1 - med_gt) / float(med_gt)

                xmed = do_median(xvals, err=0.05, vrange=[0, MX], verbose=True)
                med2 = xmed * (vmax - vmin) / MX + vmin
                err2 = abs(med2 - med_gt) / float(med_gt)

                print data.columns.values[i], med1, err1* 100, med2, err2* 100, med_gt 
                d += [(data.columns.values[i], [med1, err1* 100, med2, err2* 100, med_gt])]

            except:
                pass 
                # print data.iloc[0:num, i]

        frame = pd.DataFrame.from_items(d, orient="index", columns=["Median (0.25)", "Error (%)", "Median (0.05)", "Error (%)", "Truth"])
        print frame.to_latex(float_format=(lambda x: u"%1.1f" % x))

    if args.time:
        test_median()

    if args.size:
        size_vs_error()
    
    if args.quality:
        no_test_DP_median()


    if args.cprof:
        import cProfile
        cProfile.run("test_median()", sort="tottime")
        

    if args.lprof:
        from line_profiler import LineProfiler

        profile = LineProfiler(test_median, CountSketchCt.estimate, CountSketchCt.aggregate,
            Ct.__add__, EcPt.__add__, EcPt.__neg__, EcPt.__copy__,)
        profile.run("test_median()")
        profile.print_stats()
