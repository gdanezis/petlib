## An example of how to implement an engine for Zero-Knowledge
#  Proof of Discrete Log representations using Brands' and 
#  Camenisch's extensions to the basic Schnor proof.
#  
# For details of what is doing on see Chapter 3:
# "Rethinking Public Key Infrastructures and Digital Certificates
# Building in Privacy" By Stefan Brands, MIT Press (2000)
# On-line: http://www.credentica.com/the_mit_pressbook.html


from petlib.ec import EcGroup 
from petlib.bn import Bn 
from hashlib import sha256


def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state)
    return H.digest()

class Val:
    """A common ansestor for all values"""
    def val(self, env):
        return env[self.name]

class Pub(Val):
    """Defines a public value, given by the prover"""
    def __init__(self, zkp, name):
        self.name = name
        self.zkp = zkp
        assert name not in zkp.Pub
        zkp.Pub[name] = self

class ConstPub(Pub):
    """Defines a public value from the environment"""
    def __init__(self, zkp, name):
        self.name = name
        self.zkp = zkp
        assert name not in zkp.Const
        zkp.Const[name] = self

class Sec(Val):
    """Defines a secret value of the prover"""
    def __init__(self, zkp, name):
        self.name = name
        self.zkp = zkp
        assert name not in zkp.Sec
        zkp.Sec[name] = self

class Gen(object):
    """Represents a public generator, given by the prover"""
    def __init__(self, zkp, name=None, prove=False, constuction=None):
        self.name = name
        self.zkp = zkp

        if name:
            assert name not in zkp.Pub
            zkp.Pub[name] = self

        self.prove = prove
        self.constuction = constuction

    def get_repr(self):
        if self.name or self.constuction[0] == "Gen*":
            return [self]
        elif self.constuction[0] == "Gen+":
            return self.constuction[1:]
        
        raise Exception("Unknown Gen type")

    def __add__(self, other):
        assert isinstance(other, Gen)
        assert self.zkp == other.zkp
        assert self.prove == other.prove

        prove = self.prove or other.prove
        c = ["Gen+"] + self.get_repr() + other.get_repr()
        newG = Gen(self.zkp, prove=prove, constuction=c)
        return newG

    def __rmul__(self, other):
        assert isinstance(other, Val)
        assert not self.prove
        assert self.zkp == other.zkp

        prove = isinstance(other, Sec)
        if self.constuction and self.constuction[0] == "Gen*":
            c = self.constuction + [other]
        else:        
            c = ["Gen*", self, other]
        
        return Gen(self.zkp, constuction=c, prove=prove)

    def val(self, env):
        """Returns the value of this variable"""

        ## In case of a named value just return it.
        if self.name:
            return env[self.name]

        ## In case of a "+" add all parts
        if self.constuction[0] == "Gen+":
            gather = [v.val(env) for v in self.constuction[1:]]
            Sum = None
            for v in gather:
                if Sum is None:
                    Sum = v
                else:
                    Sum = v + Sum
            return Sum

        if self.constuction[0] == "Gen*":
            base = self.constuction[1].val(env)
            exps = [v.val(env) for v in self.constuction[2:]]
            Prod = 1
            for v in exps:
                Prod = v * Prod
            return Prod * base

        raise Exception("Unknown case")

class ConstGen(Gen):
    """Represents a generator constant in the environment"""
    def __init__(self, zkp, name):
        Gen.__init__(self, zkp, name=name)
        
        assert name not in self.zkp.Const
        self.zkp.Const[name] = self

class ZKProof(object):
    """A class representing a number of associated ZK Proofs."""

    def __init__(self, G):
        """Define a proof object, and the group in which the proof
        is to be carried."""
        self.G = G

        self.Const = {}
        self.Pub = {}
        self.Sec = {}
        self.proofs = []

    def add_proof(self, lhs, rhs):
        """Adds a proof obligation to show the rhs is the representation of the lhs"""
        assert isinstance(lhs, Gen)
        assert lhs.prove == False
        assert isinstance(rhs, Gen)
        assert rhs.prove == True
        assert self == lhs.zkp == rhs.zkp
        
        self.proofs += [(lhs, rhs)]

    def get(self, vtype, name):
        """Returns a number of proof variables of a certain type"""
        if isinstance(name, str):
            assert vtype in [Gen, ConstGen, Sec, Pub, ConstPub] 
            return vtype(self, name)
        if isinstance(name, list):
            return [vtype(self, n) for n in name]

        raise Exception("Wrong type of names: str or list(str)")

    def _check_env(self, env):
        variables = self.Const.keys() \
                    + self.Pub.keys() \
                    + self.Sec.keys()

        for v in variables:
            assert v in env

    def build_proof(self, env, message=""):
        """Generates a proof within an environment of assigned public and secret variables."""

        self._check_env(env)

        G = self.G
        order = G.order()

        ## Make a list of all the public state
        state = ['ZKP', G.nid(), message]

        for v in sorted(self.Const.keys()):
            state += [env[v]]
        for v in sorted(self.Pub.keys()):
            state += [env[v]]

        ## Set witnesses for all secrets
        witnesses = dict(env.items())
        for w in self.Sec.keys():
            assert w in witnesses
            witnesses[w] = order.random()

        ## Compute the first message and add it to the state
        for base, expr in self.proofs:
            Cw = expr.val(witnesses)
            state += [Cw]

        ## Compute the challenge using all the state
        hash_c = challenge(state)
        c = Bn.from_binary(hash_c) % order

        ## Compute all the resources
        responses = dict(env.items())
        for w in self.Sec.keys():
            responses[w] = (witnesses[w] - c * env[w]) % order
         
        ## This is purely a sanity check
        #for base, expr in self.proofs:
        #    Cw = expr.val(witnesses)
        #    Cr = expr.val(responses)
        #    Cx = expr.val(env)
        #    print Cw
        #    assert Cx == base.val(env)
        #    assert Cw == Cr + c * Cx

        for v in self.Const:
            del responses[v]

        return (c, responses)

    def verify_proof(self, env, sig, message=""):
        """Verifies a proof within an environment of assigned public only variables."""

        ## Select the constants for the env
        env_l = [(k,v)for  k,v in env.items() if k in self.Const]
        c, responses = sig
        responses = dict(responses.items() + env_l)

        ## Ensure all variables we need are here
        self._check_env(responses)

        ## Define the maths group we work in
        G = self.G
        order = G.order()

        ## Make a list of all the public state
        state = ['ZKP', G.nid(), message]
        for v in sorted(self.Const.keys()):
            state += [responses[v]]
        for v in sorted(self.Pub.keys()):
            state += [responses[v]]

        ## Compute the first message and add it to the state
        for base, expr in self.proofs:
            Cr = expr.val(responses)
            Cx = base.val(responses)
            Cw = Cr + c * Cx
            state += [Cw]
         
        ## Compute the challenge using all the state
        hash_c = challenge(state)
        c_prime = Bn.from_binary(hash_c) % order

        ## Check equality
        return (c == c_prime)
        

def test_basic():
    zk = ZKProof(None)

    g = zk.get(ConstGen, "g")
    h = zk.get(ConstGen, "h")
    Gone = zk.get(ConstGen, "1")
    x = zk.get(Sec, "x")
    o = zk.get(Sec, "o")
    y = zk.get(Pub, "y")
    one = zk.get(ConstPub, "1g")

    Cx = zk.get(Gen, "Cx")

    Cxp =  x*g + o*(y * h)

    zk.add_proof(Cx, Cxp)

    print zk.Const.keys()
    print zk.Pub.keys()
    print zk.Sec.keys()

def test_Pedersen():

    # Define an EC group
    G = EcGroup(713)
    order = G.order()

    ## Proof definitions
    zk = ZKProof(G)
    g, h = zk.get(ConstGen, ["g", "h"])
    x, o = zk.get(Sec, ["x", "o"])
    Cxo = zk.get(Gen, "Cxo")
    zk.add_proof(Cxo, x*g + o*h)

    # A concrete Pedersen commitment
    ec_g = G.generator()
    ec_h = order.random() * ec_g
    bn_x = order.random()
    bn_o = order.random()
    ec_Cxo = bn_x * ec_g + bn_o * ec_h

    # Execute the proof
    env = {
        "g": ec_g,
        "h": ec_h,    
        "Cxo": ec_Cxo,
        "x": bn_x,
        "o": bn_o
        }
    sig = zk.build_proof(env)

    # Execute the verification
    env_verify = {
        "g": ec_g,
        "h": ec_h
        }

    assert zk.verify_proof(env_verify, sig)
    