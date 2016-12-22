from petlib.ec import EcGroup, EcPt
import time

timings = []
curves = EcGroup.list_curves()

for gid in curves:
    G = EcGroup(gid)
    gx = G.order().random() * G.generator()

    rnd = [G.order().random() for _ in range(100)]

    t0 = time.time()
    for r in rnd:
        r * gx
    t1 = time.time()
    timings += [((t1-t0)*1000.0, gid)]

timings = sorted(timings)
for t in timings:
    print(" %.2fms : (%s) %s" % (t[0], t[1], curves[t[1]]))