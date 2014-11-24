## An implementation of an additivelly homomorphic 
## ECC El-Gamal scheme, used in Privex.

from petlib.ec import EcGroup, EcPt

def params_gen(nid=409):
    G = EcGroup(409)
    g = G.generator()
    o = G.order()
    return (G, g, o)

def key_gen(params):
    G, g, o = params
    priv = o.random()
    pub = priv * g
    return (pub, priv)

def enc(params, pub, counter):
    assert -2**8 < counter < 2**8
    G, g, o = params

    k = o.random()
    a = k * g
    b = k * pub + counter * g
    return (a, b)

def add(params, c1, c2):
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + a2, b1 + b2)

def mul(params, c1, val):
    a1, b1 = c1
    return (val*a1, val*b1)

def randomize(params, pub, c1):
    zero = enc(params, pub, 0)
    return add(params, c1, zero)

def make_table(param):
    G, g, o = params
    table = {}
    for i in range(-1000, 1000):
        table[i * g] = i
    return table

def dec(params, table, priv, c1):
    G, g, o = params
    a,b = c1
    plain = b + (-priv * a)
    return table[plain] 


if __name__ == "__main__":
    params = params_gen()
    (pub, priv) = key_gen(params)
    table = make_table(params)

    one = enc(params, pub, 1)
    assert dec(params, table, priv, one) == 1

    tmp = add(params, one, one)
    two = randomize(params, pub, tmp)
    assert dec(params, table, priv, two) == 2

    tmp1 = mul(params, two, 2)
    four = randomize(params, pub, tmp1)
    assert dec(params, table, priv, four) == 4
