from twisted.names import dns, server, client, cache
from twisted.application import service, internet

class ResolverFeedSocket(client.Resolver):
    def __init__(self, real_servers):
        client.Resolver.__init__(self, servers=real_servers)
        self.ttl = 1

    # base32/64 | null/txt/a

    # ! un seul service !
    # si pas d'activite -> raz & envoi 0 as marshal
    #  --> last request timestamp
    # C -> S : ping_service : size + type + encoding
    # C -> S : pubkey
    # S -> C : sym_k % pubkey
    #  ...

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
            (
              dns.RRHeader(name, dns.CNAME, dns.IN, self.ttl, dns.Record_CNAME("oh", 1)),
              dns.RRHeader(name, dns.CNAME, dns.IN, self.ttl, dns.Record_CNAME("fanzifer", 1)),
              dns.RRHeader(name, dns.CNAME, dns.IN, self.ttl, dns.Record_CNAME("la", 1))
            ), # ans
            (), # auth
            () # add
        ]

    def look(self, reply_type, reply_fun, name):
        print(self, name)
        return self.ping(name)

## this sets up the application
application = service.Application('dnsserver', 99, 99) # nobody is 99

resolver = ResolverFeedSocket([('8.8.8.8', 53)])

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

# run it through twistd!
if __name__ == '__main__':
    import sys
    print "Usage: twistd -y %s" % sys.argv[0]
