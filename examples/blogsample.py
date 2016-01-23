from petlib.ec import EcGroup
from genzkp import ZKProof, ZKEnv, ConstGen, Sec

def test_blog_post():
    # Define an EC group
    G = EcGroup(713)
    print (EcGroup.list_curves()[713])
    order = G.order()

    ## Define the Zero-Knowledge proof statement
    zk = ZKProof(G)
    g, h = zk.get(ConstGen, ["g", "h"])
    x, o = zk.get(Sec, ["x", "o"])
    Cxo = zk.get(ConstGen, "Cxo")
    zk.add_proof(Cxo, x*g + o*h)

    ## Render the proof statement in Latex
    print(zk.render_proof_statement())

    # A concrete Pedersen commitment
    ec_g = G.generator()
    ec_h = order.random() * ec_g
    bn_x = order.random()
    bn_o = order.random()
    ec_Cxo = bn_x * ec_g + bn_o * ec_h

    ## Bind the concrete variables to the Proof
    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 
    env.Cxo = ec_Cxo
    env.x = bn_x 
    env.o = bn_o

    # Create the Non-Interactive Zero-Knowledge (NIZK) proof
    sig = zk.build_proof(env.get())

    # Execute the verification on the proof 'sig'
    env = ZKEnv(zk)
    env.g, env.h = ec_g, ec_h 
    env.Cxo = ec_Cxo

    assert zk.verify_proof(env.get(), sig)

if __name__ == "__main__":
    test_blog_post()
