from array import array
from struct import pack
from hashlib import sha512
from random import gauss

## Use the frequency Count sketch for Tor metrics
## See section 1.3.2 of http://people.cs.umass.edu/~mcgregor/711S12/sketches1.pdf

def hashes(item, d):
    codes = []
    i = 0
    while len(codes) < d:
        codes += list(array('I', sha512(pack("I", i) + item.encode("utf8")).digest())) 
        i += 1
    return codes[:d]

class CountSketch(object):
    def __init__(self, w, d):
        assert isinstance(w, int) and w > 0
        assert isinstance(d, int) and d > 0

        self.d, self.w = d, w
        self.store = [ [0] * w for _ in range(d) ]

    def insert(self, item):
        h = hashes(item, self.d)
        for di in range(self.d):
            self.store[di][h[di] % self.w] += 1 

    def estimate(self, item):
        h = hashes(item, self.d)
        h2 = []
        for hi in h:
            v = hi - 1 if hi % 2 == 0 else hi + 1
            h2 += [v]
        estimates = 0
        for i, [hi, hpi] in enumerate(zip(h, h2)):
            v1 = self.store[i][hi % self.w] 
            v2 = self.store[i][hpi % self.w]
            estimates += v1 - v2
        return float(estimates) / self.d

def test_hash():
    print(len(hashes("hello", 20)))
    assert len(hashes("hello", 20)) == 20

def test_inserter():
    cs = CountSketch(50, 7)
    for x in range(100):
        assert sum(cs.store[0]) == x
        cs.insert("%s" % x)

def test_estimate():
    cs = CountSketch(50, 5)
    for x in range(100):
        cs.insert("%s" % x)

    e = 0
    for x in range(100):
        e += cs.estimate("%s" % x)
    assert round(e / 100) == 1.0

    e = 0
    for x in range(100):
        e += (cs.estimate("xx%s" % x))
    assert round(e / 100) == 0.0

def test_median():
    vals = [gauss(300, 25) for _ in range (100)]
    vals += [gauss(300, 200) for _ in range (10)]
    vals = sorted([int(v) for v in vals])

    ## Compute the mediam on clear data
    median = vals[int(len(vals) / 2)]
    print(median)

    ## Build a CountSketch for the job
    cs = CountSketch(50, 5)
    for x in vals:
        cs.insert("%s" % x)

    vals2 = []
    for x in range(1000):
        vals2 += [(x, cs.estimate("%s" % x))]

    # Median estimation using the count sketch
    total = sum([vx for _, vx in vals2])
    t = 0
    i = 0
    while t < total / 2:
        t += vals2[i][1]
        res = vals2[i][0]
        i += 1
    print(res)

    # assert abs(res - median) < 30



