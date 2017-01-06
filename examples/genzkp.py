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

import pytest

def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return H.digest()

class Val:
    """A common ansestor for all values"""
    def val(self, env):
        return env[self.name]

    def tex(self):
        return "{%s}" % tex_encode(self.name)

class Pub(Val):
    """Defines a public value, given by the prover"""
    def __init__(self, zkp, name):
        self.name = name
        self.zkp = zkp
        assert name not in zkp.Pub
        zkp.Pub[name] = self

    def tex(self):
        return r"{\mathrm{%s}}" % tex_encode(self.name)


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

    def tex(self):
        ## In case of a named value just return it.
        if self.name:
            return r"{\mathrm{%s}}" % (tex_encode(self.name))

        if self.constuction[0] == "Gen+":
            gather = [v.tex() for v in self.constuction[1:]]
            Sum = " \cdot ".join(gather)
            return "{%s}" % Sum

        if self.constuction[0] == "Gen*":
            base = self.constuction[1].tex()
            exps = [v.tex() for v in self.constuction[2:]]
            exps = " \cdot ".join(exps)
            ret = "{%s}^{%s}" % (base, exps)
            return ret



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
        Gen.__init__(self, zkp, name=None)
        
        self.name = name
        assert name not in self.zkp.Const
        self.zkp.Const[name] = self

class ZKProof(object):
    """A class representing a number of associated ZK Proofs."""

    def __init__(self, G):
        """Define a proof object, and the group in which the proof
        is to be carried."""
        
        self.locked = False
        self.G = G

        self.Const = {}
        self.Pub = {}
        self.Sec = {}
        self.proofs = []

        self.arrays = {}

        self.locked = True

    def add_proof(self, lhs, rhs):
        """Adds a proof obligation to show the rhs is the representation of the lhs"""
        assert isinstance(lhs, Gen)
        assert lhs.prove == False
        assert isinstance(rhs, Gen)
        assert rhs.prove == True
        assert self == lhs.zkp == rhs.zkp
        
        self.proofs.append((lhs, rhs))

    def _check_name_ok(self, name):
        if __debug__:
            import re
            a = re.compile("^[a-zA-Z][a-zA-Z0-9_]*$")
            if a.match(name) is not None:
                return True
            return False

    def get(self, vtype, name, ignore_check = False):
        """Returns a number of proof variables of a certain type"""
        assert vtype in [Gen, ConstGen, Sec, Pub, ConstPub]

        if isinstance(name, str):
            assert self._check_name_ok(name) or ignore_check
            return self._get(vtype, name, ignore_check)

        if isinstance(name, list):
            assert all(map(self._check_name_ok, name)) or ignore_check
            return [self._get(vtype, n, ignore_check) for n in name]

        raise Exception("Wrong type of names: str or list(str)")


    def _get(self, vtype, name, ignore_check = False):
        assert isinstance(name, str)

        for D in [self.Const, self.Pub, self.Sec]:
            if name in D:
                assert isinstance(D[name], vtype)
                return D[name]

        return vtype(self, name)


    def __setattr__(self, name, value):
        if hasattr(self, "locked") and self.locked:
            assert name not in self.__dict__

            # Add the name to the zk proof
            v = self.get(value, name)
            object.__setattr__(self, name, v)
        else:
            # implement *my* __setattr__
            object.__setattr__(self, name, value)


    def get_array(self, vtype, name, number, start=0):
        """Returns an array of variables"""
        assert vtype in [Gen, ConstGen, Sec, Pub, ConstPub] 
        assert isinstance(name, str)
        assert self._check_name_ok(name)

        if name in self.arrays:
            assert self.arrays[name] == (number, start)
        else:
            self.arrays[name] = (number, start)

        names = ["%s[%i]" % (name,i) for i in range(start, start+number)]
        return self.get(vtype, names, True)

    def all_vars(self):
        variables = list(self.Const) \
                    + list(self.Pub) \
                    + list(self.Sec)
        return set(variables)

    def _check_env(self, env):
        if __debug__:
            variables = self.all_vars()

            for v in variables:
                if not v in env:
                    raise Exception("Could not find variable %s in the environment.\n%s" % (repr(v), repr(variables)))

    def render_proof_statement(self):
        s = r'$'

        if len(self.Const) > 0:
            variables = []
            for con in sorted(list(self.Const)):
                variables += ["{\mathrm{%s}}" % tex_encode(con)]
            s += r"\text{Constants: } %s \\" % (', '.join(variables))


        if len(self.Pub) > 0:
            variables = []
            for pub in sorted(list(self.Pub)):
                variables += ["{\mathrm{%s}}" % tex_encode(pub)]
            s += r"\text{Public: } %s \\" % (', '.join(variables))

        s += r"\text{NIZK}\{" + """("""
        variables = []
        for sec in sorted(list(self.Sec)):
            variables += ["{%s}" % tex_encode(sec)]
        variables = ', '.join(variables)
        s += variables

        s += r"): \\ \qquad "

        formulas = []
        for base, expr in self.proofs:
            formulas += ["%s = %s" % (base.tex(), expr.tex())]

        s += r" \wedge \\ \qquad ".join(formulas)

        s+= r'\}$'
        return s


    def build_proof(self, env, message=""):
        """Generates a proof within an environment of assigned public and secret variables."""

        self._check_env(env)

        # Do sanity check on the proofs
        if __debug__:
            for base, expr in self.proofs:
                xGen = base.val(env)
                xExpr = expr.val(env)
                try:
                    assert xGen == xExpr
                except:
                    raise Exception("Proof about '%s' does not hold." % base.name)

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
         
        for v in self.Const:
           del responses[v]

        return (c, responses)

    def verify_proof(self, env, sig, message="", strict=True):
        """Verifies a proof within an environment of assigned public only variables."""

        ## Select the constants for the env
        env_l = [(k,v) for  k,v in env.items() if k in self.Const]
        
        if __debug__ and strict:
            env_not = [k for k,v in env.items() if k not in self.Const]
            if len(env_not):
                raise Exception("Did not check: " + (", ".join(env_not)))

        c, responses = sig
        responses = dict(list(responses.items()) + env_l)

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
        
class ZKEnv(object):
    """ A class that passes all the ZK environment 
        state to the proof or verification.
    """

    def __init__(self, zkp):
        """ Initializes and ties to a specific proof. """
        ## Watch out for recursive calls, given we 
        #  redefined __setattr__
        object.__setattr__(self, "zkp", zkp)
        object.__setattr__(self, "env", {})

    def __setattr__(self, name, value):
        """ Store into a special dictionary """
        if isinstance(value, list):
            assert name in self.zkp.arrays
            number, start = self.zkp.arrays[name]
            assert len(value) == number

            for i, v in enumerate(value):
                n = "%s[%i]" % (name,start+i)
                self._set_var(n, v)
    
        else:          
            self._set_var(name, value)

    def _set_var(self, name, value):
        if not name in self.zkp.all_vars():
            raise Exception("Variable name '%s' not known." % name)
        self.env[name] = value

    def __getattr__(self, name):
        if not name in self.zkp.all_vars():
            raise Exception("Variable name '%s' not known." % name)
        return self.env[name]

    def get(self):
        """ Get the environement. """
        return self.env

import re
def tex_encode(name):
    m = re.match(r"^(.+)i\[([0-9]+)\]$", name)
    if m != None:
        return r"{%s}_{%s}" % (tex_encode(m.group(1)), m.group(2))

    m = re.match(r"^(.+)_prime$", name)
    if m != None:
        return r"{%s'}" % (tex_encode(m.group(1)))   

    m = re.match(r"^(.+)_bar$", name)
    if m != None:
        return r"{\overline{%s}}" % (tex_encode(m.group(1)))

    return name

def test_tex():
    assert "}_{" in tex_encode("helloi[10]")
    assert "'}" in tex_encode("hello_prime")
    assert r"\overline" in tex_encode("hello_bar")


def test_basic():
    zk = ZKProof(None)

    g = zk.get(ConstGen, "g")

    # Test: ok to call twice
    g2 = zk.get(ConstGen, "g")
    # return same object
    assert g == g2

    # Test: need to be of same type!
    with pytest.raises(Exception) as excinfo:
        zk.get(Pub, "g")
    print str(excinfo.value)
    assert "isinstance" in str(excinfo.value)


    h = zk.get(ConstGen, "h")
    Gone = zk.get(ConstGen, "d1")
    x = zk.get(Sec, "x")
    o = zk.get(Sec, "o")
    y = zk.get(Pub, "y")
    one = zk.get(ConstPub, "d1g")

    Cx = zk.get(Gen, "Cx")

    Cxp =  x*g + o*(y * h)

    zk.add_proof(Cx, Cxp)

    print(zk.Const.keys())
    print(zk.Pub.keys())
    print(zk.Sec.keys())

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

def test_Pedersen_Env():

    # Define an EC group
    G = EcGroup(713)
    order = G.order()

    ## Proof definitions
    zk = ZKProof(G)
    g, h = zk.get(ConstGen, ["g", "h"])
    x, o = zk.get(Sec, ["x", "o"])
    Cxo = zk.get(Gen, "Cxo")
    zk.add_proof(Cxo, x*g + o*h)

    print(zk.render_proof_statement())

    # A concrete Pedersen commitment
    ec_g = G.generator()
    ec_h = order.random() * ec_g
    bn_x = order.random()
    bn_o = order.random()
    ec_Cxo = bn_x * ec_g + bn_o * ec_h

    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 
    env.Cxo = ec_Cxo
    env.x = bn_x 
    env.o = bn_o

    sig = zk.build_proof(env.get())

    # Execute the verification
    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 

    assert zk.verify_proof(env.get(), sig)

def test_Pedersen_Shorthand():

    # Define an EC group
    G = EcGroup(713)
    order = G.order()

    ## Proof definitions
    zk = ZKProof(G)
    zk.g, zk.h = ConstGen, ConstGen
    zk.x, zk.o = Sec, Sec
    zk.Cxo = Gen
    zk.add_proof(zk.Cxo, zk.x*zk.g + zk.o*zk.h)

    print(zk.render_proof_statement())

    # A concrete Pedersen commitment
    ec_g = G.generator()
    ec_h = order.random() * ec_g
    bn_x = order.random()
    bn_o = order.random()
    ec_Cxo = bn_x * ec_g + bn_o * ec_h

    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 
    env.Cxo = ec_Cxo
    env.x = bn_x 
    env.o = bn_o

    sig = zk.build_proof(env.get())

    # Execute the verification
    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 

    assert zk.verify_proof(env.get(), sig)


def test_Pedersen_Env_missing():

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

    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 
    env.Cxo = ec_Cxo
    env.x = bn_x 
    # env.o = bn_o ## MISSING THIS ONE

    with pytest.raises(Exception) as excinfo:
        env.NOTEXISTING = bn_x
    assert "Variable name 'NOTEXISTING' not known" in str(excinfo.value)

    ## Ensure we catch missing variables
    with pytest.raises(Exception) as excinfo:
        zk.build_proof(env.get())
    assert 'Could not find variable' in str(excinfo.value)

    ## Ensure we catch false statements
    env.o = bn_o + 1    
    with pytest.raises(Exception) as excinfo:
        zk.build_proof(env.get())
    assert "Proof about 'Cxo' does not hold" in str(excinfo.value)

def test_latex_print():

    # Define an EC group
    G = EcGroup(713)
    order = G.order()

    ## Proof definitions
    zk = ZKProof(G)
    g, h = zk.get(ConstGen, ["g", "h"])
    x, o = zk.get(Sec, ["x", "o"])
    Cxo = zk.get(Gen, "Cxo")
    zk.add_proof(Cxo, x*g + o*h)

    print(zk.render_proof_statement())
    