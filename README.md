bromine
=======

Bromine is the equivalent of Iodine (https://code.kryo.se/iodine/) written in python/twisted. It is to be used with ssh -D. It doesnt do tunneling per se, it just create a local socket forwarded to a static remote socket (default to ssh).

Usage
-----

0. Clone this;
1. Get a domain and point a subdomain to your server with a NS record (see records section below);
2. Adapt config.ini;
4. `server/client$ python3 -m venv venv`
5. `server/client$ venv/bin/pip install --upgrade pip`
6. `server/client$ venv/bin/pip install twisted`
7. `server/client$ venv/bin/python setup.py install`
8. `server/client$ mkdir -pv ~/.config/bromine && cp -v config.ini ~/.config/bromine;`
9. `server/client$ venv/bin/python -m unittest`
10. `server$ sudo service systemd-resolved stop`
11. `server$ sudo venv/bin/twistd -y server.py`
12. `client$ venv/bin/python client.py`
13. `client$ ssh you@127.0.0.1 -p 2222`

Testing
-------

You can run
`python -m unittest`

You can play with some knobs in tests.py:
`bromine.CONFIG['_fickle']` and `bromine.CONFIG['_tiny']`

You can run all of the setup on localhost as a non-priviledged user,
by enabling `TESTING = True` in client.py and server.py .
Then running the server half looks like:
`client$ venv/bin/twistd -n -y server.py`
You don't need a domain / NS indirection for testing.

Bugs / Issues
-------------

I've had issues with ubuntu bionic on arm. Use the Dockerfile if you must.
You may have to stop systemd-resolved `service systemd-resolved start`, see the the output of `netstat -plnt | grep 53` on your server.

The server may complain about `builtins.OSError: [Errno 22] Invalid argument`, this is _fine_. We forward non-bromine traffic to an invalid address...

Bandwidth is _very_ limited, be careful what you run (you cannot use `browsh`, stay with `w3m`).

Please feel free to raise issues if you see anything strange.

Docker (server side)
--------------------

Clone, set up a NS redirection, and adapt config.ini then:

0. `docker build -t bromine/0 .`
1. `docker run -ti --rm -p 53:53/udp -p 53:53 bromine/0`

Records
-------

This is how my DNS looks like, see `dig abc.z.konbu.org +trace`

```
z.konbu.org.            10800   IN      NS      funyu.konbu.org.
funyu.konbu.org.        10800   IN      A       51.15.241.64
```

I use gandi.net as registrar, and I was happy with .org, until recently, see https://www.eff.org/deeplinks/2019/11/nonprofit-community-stands-together-protect-org .

Magic
-----

From trial and error, I came up with a few magic numbers:
- client.py SLOW, FAST and REQS are related to DNS query initiation timing;
- bromine/module.py FAVOR_EVEN and FAVOR_SMALL are related to random number generation;

There are numbers you can play around with in config.ini:
- ENDPOINT is the port number we connect to on the server side;
- PORT is where we wait for your connection on the client;
- N is the maximum size of the xor-systems we can build;
- RESET is the size of the ring buffer that holds our message ids;
- ACKPERIOD is how often we inform the other side that we caught up with their messages;
- WINDOW is how fast we try to include new messages into the conversation;
