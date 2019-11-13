import bromine
import sys

from twisted.names import client, dns
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint

# https://twistedmatrix.com/documents/13.1.0/core/howto/servers.html

TESTING = False
if TESTING:
    SLOW = 1e-2
    FAST = SLOW
    REQS = 2
else:
    SLOW = 1  # dont pump too fast when not busy
    FAST = 1e-2
    REQS = 5  # when busy, we may need help


class SocketInDns(Protocol):
    def __init__(self):
        if TESTING:
            self.resolver = client.Resolver(servers=[('127.0.0.1', 5553)])
        else:
            self.resolver = client.Resolver('/etc/resolv.conf')

        # data going out
        self.score_board = bromine.Scoreboard()
        self.last_ack = bromine.INVALID_MID

        # data coming in
        self.systems = bromine.Systems()

        # keep track of callbacks
        self.requested = 0  # looping call not withstanding
        LoopingCall(self.pump).start(SLOW)

    def dataReceived(self, data):
        self.score_board.push_data(data)
        reactor.callLater(FAST, self.pump)

    def clientConnectionLost(self, connector, reason):
        print('connection lost:', reason.getErrorMessage())
        sys.exit(0)

    def empty(self):
        return all(l.type_ == bromine.TYPE_ACK for l in self.score_board.backlog.values())

    def pump(self):
        self.requested -= 1
        if self.requested > REQS:
            return

        last_seen = self.systems.last_seen_remote_mid
        if last_seen % bromine.CONFIG['ackperiod'] == 0 and self.last_ack != last_seen:
            self.last_ack = last_seen
            self.score_board.push_ack(last_seen)
        else:
            self.score_board.last_seen_remote_mid = last_seen

        for d in self.systems.data:
            self.transport.write(d)

        for ack in self.systems.acks:
            remote_last_seen_remote_mid = ack[0]
            self.score_board.retire(remote_last_seen_remote_mid)

        self.systems.commit()

        host = self.score_board.transmit()
        query = dns.Query(host, dns.CNAME, dns.IN)
        task = self.resolver.queryUDP([query], [20 * SLOW])
        task.addCallback(self.ok_)
        task.addErrback(self.error_)

    def ok_(self, reply):
        for a in reply.answers:
            cname = a.payload.name.name
            self.systems.add(cname)

        if not self.empty() or len(reply.answers) > 1:
            reactor.callLater(SLOW, self.pump)
            self.requested += 1

    def error_(self, failure):
        reactor.callLater(FAST, self.pump)
        self.requested += 1


class ClientFactory(Factory):
    def buildProtocol(self, addr):
        print("connection from", addr)
        return SocketInDns()


if __name__ == '__main__':
    endpoint = TCP4ServerEndpoint(reactor, bromine.CONFIG['port'])
    endpoint.listen(ClientFactory())

    reactor.run()
