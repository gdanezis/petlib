# This is a simple implementation of a credential server using 
# the python 3 async framework. It is meant to be used as a 
# backend to generate and clear credentials.

# The general imports

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
    def __init__(self, num_pub = 1, num_priv = 1):
        self.n = num_pub + num_priv
        self.params = cred_setup()
        self.ipub, self.isec = cred_CredKeyge(self.params, self.n)


    def handle_cmd(self, reader, writer):
        sr = SReader(reader, writer)

        CMD = sr.get()
        if CMD == "FULL":
            yield from self.handle_full(sr, reader, writer)

    @asyncio.coroutine
    def handle_full(self, sr, reader, writer):

        try:
            (G, g, h, o) = self.params
            sr = SReader(reader, writer)

            # Part 1. First we write the params and the ipub values
            sr.put( (self.params, self.ipub) )

            # Part 2. Get the public key an Encrypted cred from user
            (pub, EGenc, sig_u), public_attr  = yield from sr.get()
            print(sig_u)

            # Part 3. Check and generate the credential
            if not cred_secret_issue_user_check(self.params, pub, EGenc, sig_u):
                raise Exception("Error: Issuing checks failed")

            cred_issued = cred_secret_issue(self.params, pub, EGenc, self.ipub, self.isec, public_attr)
            sr.put(cred_issued)

            [ timeout ] = public_attr

            # Part 4. Get a blinded credential & check it
            creds, sig_o, sig_openID, Service_name, Uid = yield from sr.get()
            (u, Cmis, Cup) = creds

            if not cred_show_check(self.params, self.ipub, self.isec, creds, sig_o):
                raise Exception("Error: aMAC failed")

            # Execute the verification on the proof 'sig'
            Gid = G.hash_to_point(Service_name)
    
            zk = define_proof(G)
            env2 = ZKEnv(zk)
            env2.u, env2.h = u, h
            env2.Cm0p, env2.Cm1 = Cmis[0] - (timeout * u), Cmis[1]
            env2.Uid, env2.Gid = Uid, Gid
            
            if not  zk.verify_proof(env2.get(), sig_openID):
                raise Exception("Error: ZKP failed")

            sr.put("SUCCESS")

            yield from writer.drain()
            writer.close()

        except Exception as e:
            print(e)
            sr.put("Error")


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


import pytest # requires pytest-asyncio!

def test_server(event_loop, unused_tcp_port):

    cs = CredentialServer()

    coro = asyncio.start_server(cs.handle_cmd, 
                '127.0.0.1', unused_tcp_port, loop=event_loop)
    
    @asyncio.coroutine
    def full_client(ip, port, loop):

        ## Setup the channel
        reader, writer = yield from asyncio.open_connection(
                    ip, port, loop=loop)        
        sr = SReader(reader, writer)

        sr.put("FULL")

        # Part 1. Get the params and the ipub
        (params, ipub) = yield from sr.get()
        (G, g, h, o) = params

        # User creates a public / private key pair
        keypair = cred_UserKeyge(params)

        # User packages credentials
        LT_user_ID = o.random()
        timeout = 100
        public_attr = [ timeout ]
        private_attr = [ LT_user_ID ]

        # Part 2. Send the encrypted attributes to server
        user_token = cred_secret_issue_user(params, keypair, private_attr)
        (pub, EGenc, sig_u) = user_token
        sr.put( (user_token, public_attr) )        

        # Part 3. Get the credential back
        u, EncE, sig_s = yield from sr.get()
        mac = cred_secret_issue_user_decrypt(params, keypair, u, EncE, ipub, public_attr, EGenc, sig_s)

        # Part 4. Blind and show the credential
        
        ## User Shows back full credential to issuer
        (creds, sig_o, zis) = cred_show(params, ipub, mac, sig_s, public_attr + private_attr, export_zi=True)

        ## The credential contains a number of commitments to the attributes
        (u, Cmis, Cup) = creds

        assert len(Cmis) == 2
        assert Cmis[0] == timeout * u + zis[0] * h
        assert Cmis[1] == LT_user_ID * u + zis[1] * h

        # Derive a service specific User ID
        Service_name = b"ServiceNameRP"

        Gid = G.hash_to_point(Service_name)
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

        sr.put( (creds, sig_o, sig_openID, Service_name, Uid) )


        # Check status
        resp = yield from sr.get()
        assert resp == "SUCCESS"

        writer.close()

    event_loop.create_task(coro)
    resp = event_loop.run_until_complete(full_client('127.0.0.1', unused_tcp_port, event_loop))


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
