# This is a simple implementation of a credential server using 
# the python 3 async framework. It is meant to be used as a 
# backend to generate and clear credentials.

# The general imports

import sys
sys.path += ["../examples"]

import asyncio
from io import BytesIO
from msgpack import Unpacker

from petlib.pack import encode, decode, make_encoder, make_decoder

class SReader():
    """ Define an asyncio msgpack stream decoder. """

    def __init__(self, reader, writer):
        """ Pass ina  stream reader to unmarshall msgpack objects from. """
        self.reader = reader
        self.writer = writer
        self.decoder = make_decoder()
        self.unpacker = Unpacker(ext_hook=self.decoder, encoding="utf8")
        self.obj_buf = []


    @asyncio.coroutine
    def get(self):
        """ The co-routine providing objects. """

        while len(self.obj_buf) == 0:
            buf = yield from self.reader.read(1000)

            self.unpacker.feed(buf)
            for o in self.unpacker:
                self.obj_buf.append(o)

        return self.obj_buf.pop(0)


    def put(self, obj):
        """ Write an object to the channel. """
        self.writer.write(encode(obj))


## The crypto imports

from amacscreds import cred_setup, cred_CredKeyge, cred_UserKeyge, cred_secret_issue_user, cred_secret_issue, cred_secret_issue_user_decrypt, cred_show, cred_show_check, cred_secret_issue_user_check
from genzkp import *
from petlib.pack import encode, decode


class CredentialServer():
    def __init__(self, num_pub = 3, num_priv = 1):
        self.n = num_pub + num_priv
        self.params = cred_setup()
        self.ipub, self.isec = cred_CredKeyge(self.params, self.n)


    @asyncio.coroutine
    def handle_cmd(self, reader, writer):
        try:
            sr = SReader(reader, writer)

            CMD = yield from sr.get()

            print("Executing: %s" % CMD)
            if CMD == "INFO":
                yield from self.handle_info(sr)
            elif CMD == "ISSUE":
                yield from self.handle_issue(sr)
            elif CMD == "SHOW":
                yield from self.handle_show(sr)

        except Exception as e:
            print(e)
            sr.put("Error")


    @asyncio.coroutine
    def handle_info(self, sr):
        try:
            # Part 1. First we write the params and the ipub values
            sr.put( (self.params, self.ipub) )

        except Exception as e:
            print(e)
            sr.put("Error")

        finally:
            sr.writer.close()


    @asyncio.coroutine
    def handle_issue(self, sr):

        try:

            # Part 2. Get the public key an Encrypted cred from user
            (pub, EGenc, sig_u), public_attr  = yield from sr.get()
            k, v, timeout = public_attr

            # Part 3. Check and generate the credential
            if not cred_secret_issue_user_check(self.params, pub, EGenc, sig_u):
                raise Exception("Error: Issuing checks failed")

            cred_issued = cred_secret_issue(self.params, pub, EGenc, self.ipub, self.isec, public_attr)
            sr.put(cred_issued)

        except Exception as e:
            print(e)
            sr.put("Error")


    @asyncio.coroutine
    def handle_show(self, sr):

        try:
            (G, g, h, o) = self.params

            # Part 4. Get a blinded credential & check it
            creds, sig_o, sig_openID, Service_name, Uid, public_attr = yield from sr.get()
            (u, Cmis, Cup) = creds

            [ key, value, timeout ] = public_attr

            if not cred_show_check(self.params, self.ipub, self.isec, creds, sig_o):
                raise Exception("Error: aMAC failed")

            # Execute the verification on the proof 'sig'
            Gid = G.hash_to_point(Service_name)
    
            zk = define_proof(G)
            env2 = ZKEnv(zk)
            env2.u, env2.h = u, h
            env2.Cm0p = Cmis[0] - (key * u)
            env2.Cm1p = Cmis[1] - (value * u)
            env2.Cm2p = Cmis[2] - (timeout * u)

            env2.Cm3 = Cmis[3]

            assert len(Cmis) == 4
            env2.Uid, env2.Gid = Uid, Gid
            
            if not  zk.verify_proof(env2.get(), sig_openID):
                raise Exception("Error: ZKP failed")

            sr.put("SUCCESS")

            yield from sr.writer.drain()
            sr.writer.close()

        except Exception as e:
            import traceback
            traceback.print_exc()

            print(e)
            sr.put("Error")


def define_proof(G):
    zk = ZKProof(G)
    u, h = zk.get(ConstGen, ["u", "h"])
    LT_ID, z0, z1, z2, z3 = zk.get(Sec, ["LT_ID", "z0", "z1", "z2", "z3"])
    Cm0p = zk.get(ConstGen, "Cm0p")
    Cm1p = zk.get(ConstGen, "Cm1p")
    Cm2p = zk.get(ConstGen, "Cm2p")

    Cm3 = zk.get(ConstGen, "Cm3")
    Uid = zk.get(ConstGen, "Uid")
    Gid = zk.get(ConstGen, "Gid")

    zk.add_proof(Cm0p, z0 * h)
    zk.add_proof(Cm1p, z1 * h)
    zk.add_proof(Cm2p, z2 * h)

    zk.add_proof(Cm3, LT_ID*u + z3 * h) 
    zk.add_proof(Uid, LT_ID * Gid)

    return zk


import pytest # requires pytest-asyncio!

@asyncio.coroutine
def info_client(ip, port, loop):
    """ Implement a client for the INFO command. """

    ## Setup the channel
    reader, writer = yield from asyncio.open_connection(
                ip, port, loop=loop)        
    sr = SReader(reader, writer)

    # Send the FULL command
    sr.put("INFO")

    # Part 1. Get the params and the ipub
    (params, ipub) = yield from sr.get()
    (G, g, h, o) = params

    return params, ipub

import time

@asyncio.coroutine
def issue_client(ip, port, params, ipub, keypair, public_attr, private_attr, loop, repeat=1):
    """ Implements a client for the ISSUE protocol. """

    # Part 2. Send the encrypted attributes to server
    user_token = cred_secret_issue_user(params, keypair, private_attr)
    (pub, EGenc, sig_u) = user_token

    t0 = time.monotonic()
    for _ in range(repeat):
        ## Setup the channel
        reader, writer = yield from asyncio.open_connection(
                    ip, port, loop=loop)        
        sr = SReader(reader, writer)

        # Send the FULL command
        sr.put("ISSUE")
        
        sr.put( (user_token, public_attr) )        

        # Part 3. Get the credential back
        cred = yield from sr.get()
    t1 = time.monotonic()
    if repeat > 1:
        print("CORE ISSUE time (1): %.3f sec (repeat=%s)" % ((t1-t0) / repeat, repeat))


    (u, EncE, sig_s) = cred
    mac = cred_secret_issue_user_decrypt(params, keypair, u, EncE, ipub, public_attr, EGenc, sig_s)

    return mac, user_token, cred 

@asyncio.coroutine
def show_client(ip, port, params, ipub, mac, sig_s, public_attr, private_attr, Service_name, loop, repeat=1):
    """ Implements a client for the SHOW command. """

    # Part 1. Get the params and the ipub
    (G, g, h, o) = params

    ## User Shows back full credential to issuer
    (creds, sig_o, zis) = cred_show(params, ipub, mac, sig_s, public_attr + private_attr, export_zi=True)

    [ LT_user_ID ] = private_attr
    [ key, value, timeout ] = public_attr

    ## The credential contains a number of commitments to the attributes
    (u, Cmis, Cup) = creds

    assert len(Cmis) == 4
    assert Cmis[0] == key * u + zis[0] * h
    assert Cmis[1] == value * u + zis[1] * h
    assert Cmis[2] == timeout * u + zis[2] * h

    assert Cmis[3] == LT_user_ID * u + zis[3] * h

    # Derive a service specific User ID
    Gid = G.hash_to_point(Service_name)
    Uid = LT_user_ID * Gid

    # Define the statements to be proved
    zk = define_proof(G)

    # Define the proof environemnt
    env = ZKEnv(zk)
    env.u, env.h = u, h
    
    env.Cm0p = Cmis[0] - (key * u)
    env.Cm1p = Cmis[1] - (value * u)
    env.Cm2p = Cmis[2] - (timeout * u)

    env.Cm3 = Cmis[3]    

    env.Uid, env.Gid = Uid, Gid
    env.LT_ID = LT_user_ID
    env.z0, env.z1, env.z2, env.z3  = zis[0], zis[1], zis[2], zis[3]

    sig_openID = zk.build_proof(env.get())

    t0 = time.monotonic()
    for _ in range(repeat):
        reader, writer = yield from asyncio.open_connection(
                    ip, port, loop=loop)        
        sr = SReader(reader, writer)

        # Send the FULL command
        sr.put("SHOW")
        sr.put( (creds, sig_o, sig_openID, Service_name, Uid , public_attr) )

        # Check status
        resp = yield from sr.get()
        writer.close()
    t1 = time.monotonic()
    if repeat > 1:
        print("CORE SHOW time (1): %.3f sec (repeat=%s)" % ((t1-t0) / repeat, repeat))


    return resp


def test_info_server(event_loop, unused_tcp_port):
    cs = CredentialServer()
    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)    

    event_loop.create_task(coro)
    resp = event_loop.run_until_complete(info_client('127.0.0.1', unused_tcp_port, event_loop))

    assert tuple(resp[0]) == tuple(cs.params)


def test_issue_server(event_loop, unused_tcp_port):
    cs = CredentialServer()
    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)    

    event_loop.create_task(coro)
    (G, g, h, o) = cs.params

    # User creates a public / private key pair
    keypair = cred_UserKeyge(cs.params)

    # User packages credentials
    LT_user_ID = o.random()
    timeout = 100
    key = 200
    value = 300
    public_attr = [ key, value, timeout ]
    private_attr = [ LT_user_ID ]

    resp = event_loop.run_until_complete(issue_client('127.0.0.1', unused_tcp_port, 
        cs.params, cs.ipub, keypair, public_attr, private_attr, event_loop))


def test_show_server(event_loop, unused_tcp_port):
    cs = CredentialServer()
    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)    

    event_loop.create_task(coro)

    (G, g, h, o) = cs.params

    # User creates a public / private key pair
    keypair = cred_UserKeyge(cs.params)

    # User packages credentials
    LT_user_ID = o.random()
    timeout = 100
    key = 200
    value = 300

    public_attr = [ key, value, timeout ]
    private_attr = [ LT_user_ID ]

    resp = event_loop.run_until_complete(issue_client('127.0.0.1', unused_tcp_port, 
        cs.params, cs.ipub, keypair, public_attr, private_attr, event_loop))
    mac, user_token, cred = resp

    pub, EGenc, sig_u = user_token
    u, EncE, sig_s = cred

    Service_name = b"TestService"
    resp = event_loop.run_until_complete(show_client('127.0.0.1', unused_tcp_port, 
        cs.params, cs.ipub, mac, sig_s, public_attr, private_attr, Service_name,
        event_loop))

    assert resp == "SUCCESS"

def test__server_timing(event_loop, unused_tcp_port):
    cs = CredentialServer()
    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)    

    event_loop.create_task(coro)

    (G, g, h, o) = cs.params

    # User creates a public / private key pair
    keypair = cred_UserKeyge(cs.params)

    # User packages credentials
    LT_user_ID = o.random()
    timeout = 100
    key = 200
    value = 300

    public_attr = [ key, value, timeout ]
    private_attr = [ LT_user_ID ]

    import time

    t0 = time.monotonic()
    for _ in range(10):
        resp = event_loop.run_until_complete(issue_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, keypair, public_attr, private_attr, event_loop))
    t1 = time.monotonic()
    print("ISSUE time (1): %.3f sec" % ((t1-t0) / 10))

    t0 = time.monotonic()
    coros = [issue_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, keypair, public_attr, private_attr, event_loop) for _ in range(10)]
    G = asyncio.gather(loop=event_loop, *(tuple(coros)))
    event_loop.run_until_complete(G)
    t1 = time.monotonic()
    print("ISSUE time (2): %.3f sec" % ((t1-t0) / 10))

    mac, user_token, cred = resp

    pub, EGenc, sig_u = user_token
    u, EncE, sig_s = cred

    Service_name = b"TestService"

    t0 = time.monotonic()
    for _ in range(10):
        resp = event_loop.run_until_complete(show_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, mac, sig_s, public_attr, private_attr, Service_name,
            event_loop))
    t1 = time.monotonic()
    print("SHOW time (1): %.3f sec" % ((t1-t0) / 10))

    t0 = time.monotonic()
    coros = [show_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, mac, sig_s, public_attr, private_attr, Service_name,
            event_loop) for _ in range(10)] 
    G = asyncio.gather(loop=event_loop, *(tuple(coros)))
    event_loop.run_until_complete(G)
    t1 = time.monotonic()
    print("SHOW time (2): %.3f sec" % ((t1-t0) / 10))

def test__server_timing_core(event_loop, unused_tcp_port):
    cs = CredentialServer()
    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)    

    event_loop.create_task(coro)

    (G, g, h, o) = cs.params

    # User creates a public / private key pair
    keypair = cred_UserKeyge(cs.params)

    # User packages credentials
    LT_user_ID = o.random()
    timeout = 100
    key = 200
    value = 300

    public_attr = [ key, value, timeout ]
    private_attr = [ LT_user_ID ]

    import time

    resp = event_loop.run_until_complete(issue_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, keypair, public_attr, private_attr, event_loop, repeat=10))
    
    mac, user_token, cred = resp

    pub, EGenc, sig_u = user_token
    u, EncE, sig_s = cred

    Service_name = b"TestService"

    resp = event_loop.run_until_complete(show_client('127.0.0.1', unused_tcp_port, 
            cs.params, cs.ipub, mac, sig_s, public_attr, private_attr, Service_name,
            event_loop, repeat=10))


    assert resp == "SUCCESS"

    print(define_proof(G).render_proof_statement())



if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_cmd, '127.0.0.1', 8888, loop=loop)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
