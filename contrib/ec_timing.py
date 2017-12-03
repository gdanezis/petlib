from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
import time

timings = []
curves = EcGroup.list_curves()

for gid in curves:
    G = EcGroup(gid)
    gx = G.order().random() * G.generator()

    rnd = [G.order().random() for _ in range(100)]

    t0 = time.clock()
    for r in rnd:
        dud = r * gx
    t1 = time.clock()

    repreats = 1000
    t = []
    for x in [2, 200]:
        o = Bn(2) ** x
        tests = [o.random() for _ in range(repreats)]

        tx = time.clock()
        for y in tests:
            dud = y * gx
        t += [time.clock() - tx]
        # print(x, t[-1] / repreats)
    if abs(t[0] - t[-1]) < 5.0 / 100:
        const = "CONST"
    else:
        const = "NOCONST"

    timings += [((t1-t0)*1000.0/100.0, gid, const)]


timings = sorted(timings)
for t in timings:
    if "binary" not in curves[t[1]]:
        print(" %.2fms (%s): (%s) %s" % (t[0], t[2], t[1], curves[t[1]]))