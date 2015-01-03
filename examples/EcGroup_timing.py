from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

import time

if __name__ == "__main__":
    fails = 0
    print("List of curves passing the constant-time scalar mult test:")
    for (nid, name) in sorted(EcGroup.list_curves().items()):
        G = EcGroup(nid)
        g = G.generator()
        order = G.order()
        h = order.random() * g

        repreats = 100
        t = []
        for x in range(0, 400, 100):
            o = Bn(2) ** x
            tests = [o.random() for _ in range(repreats)]

            t0 = time.clock()
            for y in tests:
                y * h
            t += [time.clock() - t0]
            # print x, t[-1] / repreats
        res = abs(t[0] - t[-1]) < 1.0 / 100
        if res:

            ps = 1.0 / (t[-1] / repreats)
            res = ["FAIL", "PASS"][res]
            print("%3d\t%s\t%2.1f/s\t%s" % (nid, res, ps, name))
        else:
            fails += 1

    print("%d fails" % fails)