from twisted.names import dns, server, client, cache
from twisted.application import service, internet
from twisted.internet.task import LoopingCall
from twisted.internet import reactor

import time
import re
import common
import random

DEBUG = True
CORRUPT = False

class ResolverFeedSocket(client.Resolver):
    def __init__(self, domain, real_servers):
        client.Resolver.__init__(self, servers=real_servers)
        self.ttl = 0

        self.sessions = {}
        self.sessions_keys = {}
        self.sessions_info = {}

        self.domain = domain
        self.skip = len(domain.split('.')) + 1

    def lookupCanonicalName(self, name, timeout = None):
        return self.look(dns.CNAME, dns.Record_CNAME, name)

    def lookupNull(self, name, timeout = None):
        return self.look(dns.NULL, dns.Record_NULL, name)

    def lookupText(self, name, timeout = None):
        return self.look(dns.TXT, dns.Record_TXT, name)

    def lookupAddress(self, name, timeout = None):
        return self.look(dns.CNAME, dns.Record_CNAME, name)

    def ping(self, name):
        return [
            (dns.RRHeader(name, dns.CNAME, dns.IN, self.ttl, dns.Record_CNAME(name, self.ttl)),),
            (), ()
        ]

    def empty(self): return [[]] * 3 # empty

    def clear(self): self.sessions = {}

    def new_session(self):
        sid = self.data[0][1:]

        # clear packets that try to reinit the key (like the last one, dup'd by a timeout)
        if sid in self.sessions_keys:
            return self.empty()

        ksize = int(self.data[1])
        content = "".join(self.payload[2:])

        if sid not in self.sessions:
            if DEBUG: print "a wild sid appears !", sid
            self.sessions[sid] = []
        elif ksize in {ks for ks, _ in self.sessions[sid]}:
            if DEBUG: print "already seen this"
            return self.empty()

        self.sessions[sid].append([ksize, content])

        # reply fast and gen key later
        if ksize == len(content):
            reactor.callLater(0.05, self.make_key, sid)
        return self.empty()

    def make_key(self, sid):
        # TODO test key on packets ?
        # TODO make tamper resistant key reconstruction ?
        parts = sorted(self.sessions[sid], reverse=True)
        max_l = len(parts[0][1])
        cipher_key = "".join(x[1] for x in parts)
        key = common.decrypt_sym(common.ub64ly(cipher_key))
        if DEBUG: print "we have a key for %s : %s"%(sid, common.b64ly(key))
        ssh_client = common.make_sok()
        ssh_client.connect(('127.0.0.1', 22))
        common.non_blocking(ssh_client)
        self.sessions_keys[sid] = [key, ssh_client]
        self.sessions_info[sid] = [common.Emitter(), common.Receptor(), max_l]

    def prepare(self):
        self.data = self.name.split('.')
        self.hash_ = self.data[-self.skip]
        self.payload = self.data[:-self.skip]

    def look(self, reply_type, reply_fun, name):
        if re.search("p.brzr.fr$", name):
            return self.ping(name)

        self.name = name
        self.prepare()

        #test for new session
        if re.search("^s", name):
            return self.new_session()

        self.guess_session_id()
        if not self.sid:
            return self.empty()

        print "name", name
        if CORRUPT and random.random() > 0.9:
            if DEBUG: print "drop !"
            return #self.empty()
        if CORRUPT and random.random() > 0.9:
            name = common.corrupt(name)
            if DEBUG: print "corrupt !", repr(name)

        self.recv_data(self.payload, self.sid, self.sok)
        return self.send_data(self.sid, self.sok)

    def send_data(self, sid, sok):
        emit, recp, max_l = self.sessions_info[sid]

        late_pid = emit.timeoutd()
        if late_pid is not None:
            pak, time_ = emit.buffer[late_pid]
            emit.buffer[late_pid] = [pak, time.time()]
            host = "%s.%s.%s"%(pak, common.sign(pak, self.key), self.domain)
            if DEBUG: print "resend", host
            return self.reply(host)

        packet = recp.get_acknak(emit.rt)

        # extract size from request : specified in payload, minus hash and packet id
        size = max_l - 10 - 7 - len(packet)
        data = common.try_read(sok, size)
        if data:
            packet = packet + "." + common.dotly(common.b64ly(data), 63)

        if packet == "0": return self.empty()

        pak, pid = emit.register_pak(packet)
        host = "%s.%s.%s"%(pak, common.sign(pak, self.key), self.domain)
        if DEBUG: print "send", host
        return self.reply(host)

    def reply(self, host):
        reply = [dns.RRHeader(
            self.name,
            dns.CNAME,
            dns.IN,
            self.ttl,
            dns.Record_CNAME(host, self.ttl)
        )]
        return [reply, (), ()]

    def recv_data(self, payload, sid, sok):
        if payload[0][0] == 'x': return

        pid = common._b64I(payload[-1])
        if DEBUG: print "see", pid

        emit, recp, max_l = self.sessions_info[self.sid]

        data_idx = common._b64I(payload[0])
        preambule = payload[1:(1+data_idx)]
        if DEBUG: print "preambule", preambule
        emit.nakackd(preambule)

        b64_payload = "".join(payload[1+data_idx:-1])
        payload = common.ub64ly(b64_payload)
        if DEBUG: print "payload", repr(payload)
        recp.write_or_pause(sok.sendall, pid, payload)

    def guess_session_id(self):
        self.sid = None
        for sid in self.sessions_keys:
            key, sok = self.sessions_keys[sid]
            signed_portion = ".".join(self.payload)
            sign_here = common.sign(signed_portion, key)
            #print(signed_portion, self.hash_, self.name)
            if sign_here == self.hash_:
                #print("got key !")
                self.sid = sid
                self.sok = sok
                self.key = key

## this sets up the application
application = service.Application('dnsserver', 99, 99) # nobody is 99 on arch
#application = service.Application('dnsserver', 65534, 65534) # nobody is 65534 on debian

resolver = ResolverFeedSocket('my.domain.org', real_servers=[('8.8.8.8', 53)])

# create the protocols
f = server.DNSServerFactory(caches=[cache.CacheResolver()], clients=[resolver])
p = dns.DNSDatagramProtocol(f)
f.noisy = p.noisy = False

# register as tcp and udp
ret = service.MultiService()
PORT = 53

for (klass, arg) in [(internet.TCPServer, f), (internet.UDPServer, p)]:
    s = klass(PORT, arg)
    s.setServiceParent(ret)

ret.setServiceParent(service.IServiceCollection(application))

LoopingCall(resolver.clear).start(3600) # TODO make it bigger

# run it through twistd!
if __name__ == '__main__':
    import sys
    print "Usage: twistd -y %s" % sys.argv[0]
