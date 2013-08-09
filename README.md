bromine
=======

Bromine is the equivalent of Iodine (code.kryo.se/iodine/) written in python/twisted. It is to be used with ssh -D. It doesnt do tunneling per se, it just create a local socket forwarded to a static remote socket (default to ssh).

Usage
=====

Get a domain. Modify server.py/client.py to adjust 'my.domain.org' to whatever you are using.
Generate a key on the server and share the public.pem on the client.
Run both sides. Connect to port 2223 on the client with ssh.

You may want to adjust the 200 in the client line, it's the max size for the packet.
I started autodetecting it and I stopped. You have the code in simple\_client.py.
