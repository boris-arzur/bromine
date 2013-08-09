import base64
import struct
import hashlib
from Crypto.Cipher import AES

import fcntl
import os, errno
import socket
import time

def try_read(sok, size):
    try:
        return sok.recv(size)
    except socket.error, e:
        err = e.args[0]
        if err == errno.EAGAIN or err == errno.EWOULDBOCK:
            return None
        else:
            raise

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def encrypt_sym(message):
    key = RSA.importKey(open('public.pem').read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt_sym(ciphertext):
    key = RSA.importKey(open('private.pem').read())
    cipher = PKCS1_OAEP.new(key)
    message = cipher.decrypt(ciphertext)
    return message

def _int(i):
    if i >= 100000:
        s = struct.pack('>I', i)
        b64I = b64ly(s)
        return b64I
    else:
        return str(i)

def _b64I(s):
    if len(s) < 6:
        return int(s)
    else:
        return struct.unpack('>I', ub64ly(s))[0]

iv = '\x00' * 16
def sign(data, key):
    hash_ = hashlib.sha256(data).digest()
    aes_engine = AES.new(key, AES.MODE_CBC, iv)
    sign = aes_engine.encrypt(hash_)
    return b64ly(sign)[:8]

def b64ly(data):
    return base64.b64encode(data, '-_').replace('=', '')

def ub64ly(data):
    missing_padding = 4 - len(data) % 4
    missing_padding = b'=' * missing_padding
    return base64.b64decode(data + missing_padding, '-_')

def non_blocking(conn):
    fcntl.fcntl(conn, fcntl.F_SETFL, os.O_NONBLOCK)

def make_sok():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#import itertools
#
#def grouper(iterable, n, fillvalue=None):
#    "Collect data into fixed-length chunks or blocks"
#    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
#    args = [iter(iterable)] * n
#    return itertools.izip_longest(fillvalue=fillvalue, *args)

def dotly(data, block_size):
    result = []
    while len(data) > 0:
        result.append(data[:block_size])
        data = data[block_size:]
    # use bytearray & memoryviews ?
    return ".".join(result)

def dotlyt(data, block_size, type_=None):
    if len(data) == 0: return ''
    if not type_: type_ = data[0]
    result = []
    block_size -= 1
    while len(data) > 0:
        result.append(data[:block_size])
        data = data[block_size:]
    # use bytearray & memoryviews ?
    return (".%s"%type_).join(result)

#BS = 16
#def pad(s):
#    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
#
#def unpad(s):
#    return s[:-ord(s[-1])]

"""
#http://stackoverflow.com/questions/6309958/encrypting-a-file-with-rsa-in-python
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import Crypto.Util.number
def encrypt_file(rsa, input, output):
    # Generate secret key
    secret_key = os.urandom(16)
    # Padding (see explanations below)
    plaintext_length = (Crypto.Util.number.size(rsa.n) - 2) / 8
    padding = '\xff' + os.urandom(16)
    padding += '\0' * (plaintext_length - len(padding) - len(secret_key))
    # Encrypt the secret key with RSA
    encrypted_secret_key = rsa.encrypt(padding + secret_key, None)
    # Write out the encrypted secret key, preceded by a length indication
    output.write(str(len(encrypted_secret_key)) + '\n')
    output.write(encrypted_secret_key)
    # Encrypt the file (see below regarding iv)
    iv = '\x00' * 16
    aes_engine = AES.new(secret_key, AES.MODE_CBC, iv)
    output.write(aes_engine.encrypt(input.read()))
"""

class Emitter:
    def __init__(self):
        self.id = 0
        self.buffer = {}
        self.rt = 1

    def register_pak(self, packet):
        pid = ".%s"%_int(self.id)
        packet += pid
        self.buffer[self.id] = [packet, time.time()]
        self.id += 1
        return packet, self.id - 1

    def nakackd(self, preambule, rt=None):
        if rt: self.rt = 0.5 * self.rt + 0.5 * rt
        self.ackd([int(x[1:]) for x in preambule if x[0] == 'a'])
        self.nakd([int(x[1:]) for x in preambule if x[0] == 'n'])

    def ackd(self, pids):
        for pid in pids:
            if pid in self.buffer:
                time_sent = self.buffer[pid][1]
                if time_sent != 0:
                    self.rt = self.rt * 0.8 + 0.2 * (time.time() - time_sent)
                del self.buffer[pid]
        print "ackd", pids, self.buffer

    def nakd(self, pids):
        for pid in pids:
            if pid in self.buffer:
                time_sent = self.buffer[pid][1]
                #  (est arrival time)      < (est nak sent)
                if time_sent - 2 * self.rt < time.time() - self.rt / 2:
                    self.buffer[pid][1] = 0 # we ask for resend
        print "nakd", pids, self.buffer

    def timeoutd(self):
        min_age = time.time() - 4 * self.rt - 1
        late_pids = [pid for pid in self.buffer if self.buffer[pid][1] < min_age]
        print self.rt, min_age, self.buffer, late_pids
        if len(late_pids) == 0:
            return None
        return min(late_pids)

class Receptor:
    def __init__(self):
        self.ack = {}
        self.nak = {}
        self.bak_pak = {}
        self.id = 0

    def ack_(self, pid):
        self.ack[pid] = time.time()
        if pid in self.nak:
            del self.nak[pid]

    def write_if_next(self, writ, pid, payload):
        print "trying", pid, "id is", self.id
        if pid == self.id:
            self.id += 1
            #self.socket.sendall(payload)
            print "wrote", repr(payload)
            writ(payload)
            return True
        return False

    def write_or_pause(self, writ, pid, payload):
        if self.write_if_next(writ, pid, payload):
            pids = sorted(self.bak_pak.iterkeys())
            for pid in pids:
                payload = self.bak_pak[pid]
                if not self.write_if_next(writ, pid, payload):
                    break
            # clean up the used ones
            self.bak_pak = {pid: self.bak_pak[pid] for pid in self.bak_pak if pid > self.id}
        elif pid > self.id:
            # we are missing one (or more) !
            # we file a complaint, and store this guy
            for i in range(self.id, pid):
                if i not in self.nak:
                    print "added", i, "to naks"
                    self.nak[i] = time.time() + 0.2
            self.bak_pak[pid] = payload
            print "waiting are pids :", [pid for pid in self.bak_pak]
        else:
            print "got dup", pid

    def get_k(self, marker, array, delta):
        if len(array) == 0: return [], {}
        t = time.time() - delta
        res = ['%s%d'%(marker, pid) for pid in array if t > array[pid]]
        ary = {pid: array[pid] for pid in array if t <= array[pid]}
        print ">", res, ary
        return res, ary

    def get_acknak(self, delta):
        acket, self.ack = self.get_k('a', self.ack, 0) # packets we have received, that were ok, we do not delay acks
        naket, self.nak = self.get_k('n', self.nak, delta) # we had problems on these, we ask for resend
        nakack = acket + naket
        if len(nakack) > 0:
            return ".".join([_int(len(nakack))] + nakack)

        return "0"

import random
def corrupt(text):
    change = int(random.random() * len(text))
    char = chr(int(random.random() * 128))
    text = bytearray(text)
    text[change] = char
    return text.decode('ascii')


if __name__ == "__main__":
    for i in xrange(int(4e9) - 100, int(4e9)):
        if i % 1000000 == 0: print 'reached', i
        if i != _b64I(_int(i)):
            print i, _int(i)
