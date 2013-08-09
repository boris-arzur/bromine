import time
import socket
import os
import common
import random

from twisted.names import client, dns
from twisted.internet import reactor
from twisted.internet.task import LoopingCall

DEBUG = True
CORRUPT = False

class Client:
    def __init__(self, domain, socket, size):
        #self.r = client.Resolver(servers=[('127.0.0.1', 53)])
        self.r = client.Resolver('/etc/resolv.conf')
        self.socket = socket

        self.key = os.urandom(32)
        self.session_id = common._int(int(1e9 * random.random()))
        self.domain = domain
        self.skip = len(domain.split('.')) + 1

        self.block_size = 63
        self.raw_size = size
        # alloc space for the dots (+ id block), and the signature
        self.size = size - len(domain) - size // self.block_size * 2 - 10

        self.emit = common.Emitter()
        self.recp = common.Receptor()
        self.rt = 1

    def send(self, data, ok_, err_, **kwargs):
        host = "%s.%s.%s"%(data, common.sign(data, self.key), self.domain)
        if DEBUG: print "send", host
        q = dns.Query(host, dns.CNAME, dns.IN)
        d = self.r.queryUDP([q], [2 * self.rt])
        if ok_: d.addCallback(ok_, **kwargs)
        if err_: d.addErrback(err_, **kwargs)

    def register(self):
        if DEBUG: print 'my key :', common.b64ly(self.key)
        cipher_key = common.b64ly(common.encrypt_sym(self.key))
        ksize = len(cipher_key)
        sess = "s%s"%self.session_id
        #print('my sess :', sess)
        size = self.size - len(sess) - 4 - 2

        bits = iter(self.key_bits(cipher_key, ksize, size, sess))
        self.next_bit(bits=bits)

    def retry_key(self, *a, **kw):
        self.send(kw['data_'], self.next_bit, self.retry_key, bits=kw['bits'], data_=kw['data_'])

    def next_bit(self, *a, **kw):
        try:
            data = next(kw['bits'])
            self.send(data, self.next_bit, self.retry_key, bits=kw['bits'], data_=data)
        except StopIteration:
            LoopingCall(self.pump).start(0.2)

    def key_bits(self, cipher_key, ksize, size, sess):
        while ksize > 0:
            payload = common.dotly(cipher_key[:size], self.block_size)
            data = "%s.%s.%s"%(sess, str(ksize), payload)
            yield data
            cipher_key = cipher_key[size:]
            ksize = len(cipher_key)

    def pump(self):
        packet = self.recp.get_acknak(2 * self.rt)

        data = common.try_read(self.socket, self.size - len(packet))
        if data:
            packet = packet + "." + common.dotly(common.b64ly(data), self.block_size)

        if packet != "0":
            packet, pid = self.emit.register_pak(packet)
            self.send(packet, self.ok_, self.err_, time_sent=time.time(), pid=pid)
        else:
            anchor = "x%s"%common._int(int(3e9 * random.random()))
            self.send(anchor, self.ok_, self.err_, time_sent=time.time(), pid=None)

    def resend(self, pid, force=False):
        packet, time_sent = self.emit.buffer[pid]
        self.emit.buffer[pid] = [packet, time_sent + 3 * self.rt * random.random()]
        self.send(packet, self.ok_, self.err_, time_sent=time.time(), pid=pid)

    def err_(self, *a, **kw):
        if DEBUG: print 'time out !', a, kw
        pid = kw['pid']
        if pid:
            self.resend(pid)

    def ok_(self, reply, **kw):
        if CORRUPT and random.random() > 0.9:
            if DEBUG: print "drop !"
            return

        self.rt = 0.8 * self.rt + 0.2 * (time.time() - kw['time_sent'])
        if 'pid' in kw and kw['pid']:
            if DEBUG: print 'ackd', kw['pid'], self.rt
            self.emit.ackd([kw['pid']])
        #else:
            #print 'was x pak', self.rt

        for a in reply.answers:
            cname = a.payload.name.name
            if DEBUG: print "recv", cname
            if CORRUPT and random.random() > 0.9:
                cname = common.corrupt(cname)
                if DEBUG: print "corrupt !", repr(cname)
            data = cname.split('.')

            signed_part = ".".join(data[:-self.skip])
            hash_ = data[-self.skip]
            sign_here = common.sign(signed_part, self.key)
            pid = common._b64I(data[-self.skip-1])
            if sign_here != hash_:
                if DEBUG: print "bad sig"
                # when the other side cant prove it's id, we dont believe in anything he says, even pid...
                #self.recp.nak.append([pid, time.time()])
                return

            if DEBUG: print "see :", pid
            preambule_l = common._b64I(data[0])
            preambule = data[1:preambule_l]
            self.emit.nakackd(preambule, rt=self.rt)

            payload = common.ub64ly("".join(data[(preambule_l + 1):-(self.skip+1)]))
            self.recp.ack_(pid)
            self.recp.write_or_pause(self.socket.sendall, pid, payload)

if __name__ == '__main__':
    HOST = '127.0.0.1'
    PORT = 2223

    s = common.make_sok()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)

    conn, addr = s.accept()
    common.non_blocking(conn)

    # get size max, get encoding
    if DEBUG: print 'Got connection'
    cli = Client('my.domain.org', conn, 200)
    cli.register()

    reactor.run()
