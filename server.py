import bromine
import pwd

from twisted.names import dns, server, client, cache
from twisted.application import service, internet
from twisted.internet.task import LoopingCall
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol

TESTING = False
DOMAIN = bromine.CONFIG['domain'].encode('ascii')


class SocketPump(Protocol):
    def __init__(self, channel_id):
        self.channel_id = channel_id

        # data going out
        self.score_board = bromine.Scoreboard()
        self.last_ack = bromine.INVALID_MID

        # data coming in
        self.systems = bromine.Systems()

    def dataReceived(self, data):
        self.score_board.push_data(data)

    def empty(self):
        return all(bromine.get_type(l) == bromine.TYPE_ACK for l in self.score_board.backlog.values())

    def pump(self, data):
        if data is not None:
            self.systems.add(data)

        last_seen = self.systems.last_seen_remote_mid
        if last_seen % bromine.CONFIG['ackperiod'] == 0 and self.last_ack != last_seen:
            self.last_ack = last_seen
            self.score_board.push_ack(last_seen)
        else:
            self.score_board.last_seen_remote_mid = last_seen

        for ack in self.systems.acks:
            remote_last_seen_remote_mid = ack[0]
            self.score_board.retire(remote_last_seen_remote_mid)

        # when transport not ready: do not write, do not commit
        if self.transport is not None:
            for d in self.systems.data:
                self.transport.write(d)

            self.systems.commit()

        host = self.score_board.transmit()
        return host


class DnsInSocket(client.Resolver):
    def __init__(self):
        INVALID = ('0.0.0.0', 0)  # do not relay queries
        client.Resolver.__init__(self, servers=[INVALID])
        self.sockets = {}

    def ensure_channel_open(self, chid):
        if chid in self.sockets:
            return self.sockets[chid]

        socket = SocketPump(chid)
        point = TCP4ClientEndpoint(
            reactor, "localhost", bromine.CONFIG['endpoint'])
        connectProtocol(point, socket)
        self.sockets[chid] = socket
        return socket

    def lookupCanonicalName(self, name, timeout=None):
        if name[-len(DOMAIN):] != DOMAIN:
            return [(), (), ()]

        transmission = bromine.from_address(name)
        chid = bromine.get_channel_id(transmission)
        socket = self.ensure_channel_open(chid)
        host = socket.pump(name)
        reply = [dns.RRHeader(
            name,
            dns.CNAME,
            dns.IN,
            0,
            dns.Record_CNAME(host, 0)
        )]

        if not socket.empty():
            # more bangs in that packet, same bucks
            # + client understands it needs to pull some more
            host = socket.pump(None)
            reply.append(dns.RRHeader(
                name,
                dns.CNAME,
                dns.IN,
                0,
                dns.Record_CNAME(host, 0)
            ))

        return [reply, (), ()]


resolver = DnsInSocket()

# create the protocols
f = server.DNSServerFactory(caches=[cache.CacheResolver()], clients=[resolver])
p = dns.DNSDatagramProtocol(f)
f.noisy = p.noisy = False

# register as tcp and udp
ret = service.MultiService()
if TESTING:
    PORT = 5553
else:
    PORT = 53

for (klass, arg) in [(internet.TCPServer, f), (internet.UDPServer, p)]:
    s = klass(PORT, arg)
    s.setServiceParent(ret)

if TESTING:
    import os
    uid = os.getuid()
else:
    uid = pwd.getpwnam("nobody").pw_uid

application = service.Application('dnsserver', uid, uid)
ret.setServiceParent(service.IServiceCollection(application))

if __name__ == '__main__':
    import sys
    print("Usage: sudo twistd3 -y /full/path/server.py")
