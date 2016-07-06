from amacscreds import cred_setup, cred_CredKeyge, cred_UserKeyge, cred_secret_issue_user, cred_secret_issue, cred_secret_issue_user_decrypt, cred_show, cred_show_check
from genzkp import *

def test_openID_blind():
    ## Setup from credential issuer.
    params = cred_setup()
    (G, g, h, o) = params

    ## Derive a fresh, long term secret for user
    LT_user_ID = o.random()
    timeout = 100

	## Attriutes we want to encode
    public_attr = [ timeout ]
    private_attr = [ LT_user_ID ]
    n = len(public_attr) + len(private_attr)

    ipub, isec = cred_CredKeyge(params, n)

	## User generates keys and encrypts some secret attributes
    #  the secret attributes are [10, 20]
    keypair = cred_UserKeyge(params)
    pub, EGenc, sig = cred_secret_issue_user(params, keypair, private_attr)
    
     ## The issuer checks the secret attributes and encrypts a amac
    #  It also includes some public attributes, namely [30, 40].
    u, EncE, sig = cred_secret_issue(params, pub, EGenc, ipub, isec, public_attr)
    
    ## The user decrypts the amac
    mac = cred_secret_issue_user_decrypt(params, keypair, u, EncE, ipub, public_attr, EGenc, sig)
    
    ## User Shows back full credential to issuer
    (creds, sig, zis) = cred_show(params, ipub, mac, sig, public_attr + private_attr, export_zi=True)

    ## The credential contains a number of commitments to the attributes
    (u, Cmis, Cup) = creds

    assert len(Cmis) == 2
    assert Cmis[0] == timeout * u + zis[0] * h
    assert Cmis[1] == LT_user_ID * u + zis[1] * h

    # Derive a service specific User ID
    Gid = G.hash_to_point("ServiceNameRP")
    Uid = LT_user_ID * Gid

    # Define the statements to be proved
    zk = define_proof(G)

    # Define the proof environemnt
    env = ZKEnv(zk)
    env.u, env.h = u, h
    env.Cm0p, env.Cm1 = Cmis[0] - (timeout * u), Cmis[1]
    env.Uid, env.Gid = Uid, Gid
    env.LT_ID = LT_user_ID
    env.z0, env.z1 = zis[0], zis[1]

    sig_openID = zk.build_proof(env.get())

    ## Issuer / IdP checks the credential is valid
    assert cred_show_check(params, ipub, isec, creds, sig)

    # Execute the verification on the proof 'sig'
    env2 = ZKEnv(zk)
    env2.u, env2.h = u, h
    env2.Cm0p, env2.Cm1 = Cmis[0] - (timeout * u), Cmis[1]
    env2.Uid, env2.Gid = Uid, Gid
    
    assert zk.verify_proof(env2.get(), sig_openID)

def define_proof(G):
	zk = ZKProof(G)
	u, h = zk.get(ConstGen, ["u", "h"])
	LT_ID, z0, z1 = zk.get(Sec, ["LT_ID", "z0", "z1"])
	Cm0p = zk.get(ConstGen, "Cm0p")
	Cm1 = zk.get(ConstGen, "Cm1")
	Uid = zk.get(ConstGen, "Uid")
	Gid = zk.get(ConstGen, "Gid")

	zk.add_proof(Cm0p, z0 * h)
	zk.add_proof(Cm1, LT_ID*u + z1 * h)	
	zk.add_proof(Uid, LT_ID * Gid)

	return zk

