from twisted.names import dns
from twisted.names import client
r = client.Resolver(servers=[('8.8.8.8', 53)])

import random

size = 2
ok_size = 0
fl_size = None

def try_():
    test = ""
    for i in range(size):
        test += str(int(10 * random.random()))
        if i % 63 == 1:
            test += "."
    print "try : ", len(test), "chars"
    q = dns.Query(test + ".i.brzr.fr", dns.A, dns.IN)
    d = r.queryUDP([q], [2])
    d.addCallbacks(ok_, err_)

def err_(msg):
    global size
    global fl_size
    if not fl_size or fl_size > size:
        fl_size = size
    print "fl"
    print "ok_size", ok_size, "fl_size", fl_size
    if fl_size <= ok_size + 1:
        print "finished"
        import sys
        sys.exit(0)

    size = ok_size + int((fl_size - ok_size) / 2)
    try_()

def ok_(msg):
    global size
    global ok_size
    #if msg: print(msg.answers[0].payload)
    if ok_size < size:
        ok_size = size
    print "ok"
    if fl_size:
        size = ok_size + 1 + int((fl_size - ok_size) / 2)
    else:
        size *= 2
    try_()

from twisted.internet import reactor
try_()
reactor.run()
