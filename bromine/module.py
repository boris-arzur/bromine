import base64
import itertools
import configparser
import math
import os
import random
import struct

config_path = os.path.expanduser('~/.config/bromine/config.ini')
parsed = configparser.ConfigParser()
parsed.read(config_path)

CONFIG_INT_KEYS = {'endpoint', 'port', 'n', 'reset', 'ackperiod', 'window'}


def to_int(k, v):
    return int(v) if k in CONFIG_INT_KEYS else v


CONFIG = {k: to_int(k, parsed['DEFAULT'][k]) for k in parsed['DEFAULT']}
assert(CONFIG['window'] > CONFIG['ackperiod'])
assert(CONFIG['n'] % 2 == 1)

# https://en.wikipedia.org/wiki/Hostname
# Hostnames are composed of a series of labels concatenated with dots.
# Each label must be from 1 to 63 characters long, and the entire hostname
# including the delimiting dots, but not a trailing dot, has a maximum of
# 253 ASCII characters.
NAME_MAX = 253
SUB_NAME_MAX = 63
FORBIDDEN_FIRST = b"-"[0]


def valid_dns_name(address, explain=False):
    def sub_test(sub):
        len_ = len(sub)
        valid_len = len_ > 0 and len_ <= SUB_NAME_MAX
        valid_first = len_ > 0 and sub[0] != FORBIDDEN_FIRST
        return valid_len and valid_first

    valid_len = len(address) < NAME_MAX
    valid_subs = all(sub_test(s) for s in address.split(b'.'))
    return valid_len and valid_subs


def max_size():
    if '_tiny' in CONFIG:
        # for testing purposes
        return CONFIG['_tiny']

    domain_free_size = NAME_MAX - len(CONFIG['domain'])
    num_dots = domain_free_size / SUB_NAME_MAX
    to_base64 = 0.7  # theoritically 3/4, but we have small strings
    return int((domain_free_size - num_dots) * to_base64)


def to_b64(data):
    b64 = base64.b64encode(data, b'-_')
    return b64.replace(b'=', b'')


def from_b64(data):
    missing_padding = 4 - len(data) % 4
    missing_padding = b'=' * missing_padding
    return base64.b64decode(data + missing_padding, b'-_')


def to_address(data):
    if '_fickle' in CONFIG and random.random() < CONFIG['_fickle']:
        # for testing purposes
        return None

    assert(len(data) > 0)
    tail = CONFIG['domain'].encode("ascii")

    def insert_dots(split):
        body = b'.'.join(
            b64[e:(e+split)] for e in range(0, len(b64), split))
        full_address = b'_' + body + b'.' + tail
        if valid_dns_name(full_address):
            return full_address
        return None

    b64 = to_b64(data)

    dotted = insert_dots(SUB_NAME_MAX - 1)
    if dotted is not None:
        return dotted

    # replace some char by dots
    chars = list(set(b64) - set(b"-_"))
    random.shuffle(chars)  # reduce duplicate requests
    for c in chars:
        as_byte = c.to_bytes(1, byteorder='little')
        candidate = b64.replace(as_byte, b'.')
        full_address = as_byte + candidate + b'.' + tail
        if valid_dns_name(full_address):
            return full_address

    # margin is how many dots we can fit in the body
    # 2 stands for the first "_" & the connecting "." between body and tail
    margin = NAME_MAX - len(b64) - len(tail) - 2
    min_split = int(len(b64) / margin)
    for split in range(min_split, SUB_NAME_MAX - 2):
        dotted = insert_dots(split)
        if dotted is not None:
            return dotted

    return None


def from_address(address):
    first = address[0].to_bytes(1, byteorder='little')
    sub = address[1:-1-len(CONFIG['domain'])]

    if first == b'_':
        return from_b64(sub.replace(b'.', b''))

    return from_b64(sub.replace(b'.', first))

# https://docs.python.org/3/library/struct.html#functions-and-exceptions
# https://docs.python.org/3/library/stdtypes.html#int.to_bytes
# https://stackoverflow.com/questions/22593822/doing-a-bitwise-operation-on-bytes

# one transmission is:
# transmission = chid | mid_0 | ... | mid_N | payload_transmission
# u8 channel_id = chid encodes a number to allow for multiple clients
# u16 message_id = mid helps us do xor-encoding of messages
# N is a config number, reflecting the complexity of our systems
# For data, the total overhead in byte equals 1 for chid, + 2 * n for system header, + 1 for payload type, + 1 for data length
# mids make up a ringbuffer like structure, where we reuse old mids when we reach the end of the allotment (see CONFIG['reset'])


OVERHEAD = 1 + 2 * CONFIG['n'] + 1
TYPE_NONE = 0  # invalid
# payload ACK: u16 remote last seen mid + u16 local oldest (smallest in the ringbuffer order) mid + random bytes
# payload DATA: bytes[length]
TYPE_ACK = 1
TYPE_DATA = 2


def generate_channel_id():
    return random.randint(1, 255)


def get_channel_id(transmission):
    return struct.unpack_from("<B", transmission)[0]


def ring_distances(x, y):
    min_ = min(x, y)
    max_ = max(x, y)
    end = CONFIG['reset']
    direct = max_ - min_
    circular = end - max_ + min_
    return (direct, circular)


def ring_difference(x, y):
    return min(ring_distances(x, y))


def ring_compare(x, y):
    # old school cmp like function
    if x == y:
        return 0

    direct, circular = ring_distances(x, y)

    if circular < direct:
        # it is likely we wrapped
        if x < y:
            # x is close to 0, y close to the end
            # so x is greater than y
            return 1
        else:
            return -1
    else:
        if x < y:
            # x and y are in the middle of the buffer,
            # classic order applies
            return -1
        else:
            return 1


INVALID_MID = 0


def ring_successor(mid, n=1):
    end = CONFIG['reset']
    # dont use 0, or end
    return 1 + (mid + n - 1) % (end - 1)


def random_count(upper):
    # we want an int for the size of the system,
    # we like small even numbers
    # e.g. when n == 4, not to scale:
    # 0                                 1
    # |<---0---->|<-1->|<--2-->|<3>|<-4>|
    FAVOR_EVEN = 0.4  # 0.6
    FAVOR_SMALL = 0.2  # 0.3
    x = random.random()
    y = random.random()
    m = math.atan(FAVOR_SMALL * (upper + 1))  # upper + 1 because of truncation
    k = int(math.tan(x * m) / FAVOR_SMALL)
    if k % 2 == 1 and y < FAVOR_EVEN:
        # spontaneous decay of odd to even !
        k -= 1
    return k


def make_data(data):
    footer = struct.pack("<B", TYPE_DATA)
    return data + footer


def make_ack(last_seen_remote_mid, oldest_local_mid):
    header = struct.pack("<HH", last_seen_remote_mid, oldest_local_mid)
    footer = struct.pack("<B", TYPE_ACK)
    size = max_size() - OVERHEAD - 4
    # helps dedup requests, helps with to_address failure
    pad = random.getrandbits(size * 8)
    as_bytes = pad.to_bytes(size, byteorder='little')
    return header + as_bytes + footer


def get_type(payload):
    return struct.unpack_from("<B", payload, len(payload) - 1)[0]


def parse_ack(payload):
    return struct.unpack_from("<HH", payload)


def parse_data(payload):
    return payload[:-1]


class System:
    def __init__(self):
        self.mids = []
        self.payload = 0

    def mix(self, mid, data):
        self.mids.append(mid)
        self.payload ^= int.from_bytes(data, byteorder='little')
        return self

    def to_transmission(self, chid):
        n = CONFIG['n']
        assert(n >= len(self.mids))
        mids = self.mids + (n - len(self.mids)) * [0]
        header = struct.pack("<B%dH" % n, *([chid] + mids))
        length = (self.payload.bit_length() + 7) // 8
        assert(length <= max_size())
        payload_bytes = self.payload.to_bytes(length, byteorder='little')
        return header + payload_bytes

    def to_address(self, chid):
        transmission = self.to_transmission(chid)
        address = to_address(transmission)
        return address

    def from_transmission(self, transmission):
        n = CONFIG['n']
        chid, *self.mids = struct.unpack_from("<B%dH" % n, transmission)
        self.mids = tuple(x for x in self.mids if x != 0)
        self.payload = int.from_bytes(
            transmission[(2 * n + 1):], byteorder='little')
        return self


class Systems:
    def __init__(self):
        self.systems = {}
        self.oldest_remote_mid = INVALID_MID
        self.last_seen_remote_mid = INVALID_MID
        self.tries = 0
        self.acks = []
        self.data = []

    def _simplify(self, step):
        news = {}
        to_del = set()
        for s in step:
            set_s = set(s)
            len_s = len(s)
            for t in self.systems:
                c = set_s.symmetric_difference(t)
                len_c = len(c)
                if len_c > 0 and len_c < len_s:
                    new = tuple(c)
                    if new not in self.systems:
                        payload_s = self.systems[s]
                        payload_t = self.systems[t]
                        news[new] = payload_s ^ payload_t

                    # c and s are equivalent anyway, remove
                    # the most complex
                    to_del.add(s)

        for n in news:
            self.systems[n] = news[n]

        for s in to_del:
            del self.systems[s]

        if len(news) > 0:
            self._simplify(news)

    def _extract(self):
        target_mid = ring_successor(self.last_seen_remote_mid)
        key = (target_mid,)
        if key in self.systems:
            # looks like the simplify step got us something useable
            self.tries = 0
            payload = self.systems[key]
            length = (payload.bit_length() + 7) // 8
            as_bytes = payload.to_bytes(length, byteorder='little')
            type_ = get_type(as_bytes)
            # removing things for systems is done in trim()

            if type_ == TYPE_ACK:
                ack = parse_ack(as_bytes)
                self.oldest_remote_mid = ack[1]
                self.acks.append(ack)
            elif type_ == TYPE_DATA:
                slice_ = parse_data(as_bytes)
                self.data.append(slice_)
            else:
                assert(not "payload is corrupt")

            self.updated = True
            self.last_seen_remote_mid = target_mid
            self._extract()  # do it again
        else:
            self.tries += 1

    def _trim(self):
        if self.oldest_remote_mid == 0:
            return

        now = self.oldest_remote_mid
        def too_old(mid): return ring_compare(mid, now) <= 0

        to_trim = set()
        for mids in self.systems:
            if any(too_old(mid) for mid in mids):
                to_trim.add(mids)

        for k in to_trim:
            del self.systems[k]

    # push data in
    def add(self, name):
        transmission = from_address(name)
        system = System().from_transmission(transmission)
        self.systems[system.mids] = system.payload

        self._simplify([system.mids])
        self._extract()
        self._trim()

    # when done querying data out
    def commit(self):
        self.data = []
        self.acks = []


class Scoreboard:
    def __init__(self):
        self.chid = generate_channel_id()
        self.mid = INVALID_MID
        self.last_seen_remote_mid = INVALID_MID
        self.backlog = {}
        self.sent = set()

    def allocate_mid(self):
        next_mid = ring_successor(self.mid)
        assert(next_mid not in self.backlog)
        self.mid = next_mid
        return next_mid

    def oldest_local_mid(self):
        oldest_local_mid = INVALID_MID
        for mid in self.backlog:
            if oldest_local_mid == INVALID_MID or ring_compare(mid, oldest_local_mid) <= 0:
                oldest_local_mid = mid

        return oldest_local_mid

    def push_data(self, data):
        size = max_size() - OVERHEAD
        for start in range(0, len(data), size):
            slice_ = data[start:start+size]
            mid = self.allocate_mid()
            self.backlog[mid] = make_data(slice_)

    def push_ack(self, last_seen_remote_mid=INVALID_MID):
        mid = self.allocate_mid()
        if last_seen_remote_mid != INVALID_MID:
            # transmit() needs to generate an ack from thin air
            # when backlog is empty
            self.last_seen_remote_mid = last_seen_remote_mid
        self.backlog[mid] = make_ack(
            self.last_seen_remote_mid, self.oldest_local_mid())

    def retire(self, remote_last_seen_remote_mid):
        # remote_last_seen_remote_mid is a local number!
        to_retire = set()
        for mid in self.backlog:
            if ring_compare(mid, remote_last_seen_remote_mid) <= 0:
                # mid is older, i.e. already seen by remote
                to_retire.add(mid)

        for mid in to_retire:
            del self.backlog[mid]

            # also cleanup the history of sent composite systems,
            # see select_system
            def remove_mid(mids): return tuple(m for m in mids if m != mid)
            self.sent = {remove_mid(s) for s in self.sent}

    def mix_system(self, selection):
        system = System()
        for mid in selection:
            system.mix(mid, self.backlog[mid])

        return system.to_address(self.chid)

    def random_sample(self, source, tries):
        n = CONFIG['n']
        max_count = min(len(source), n)
        for _ in range(tries):
            # we like odd, small, >0; we made random_count
            # live in [0,n] biased toward even, so +1
            count = 1 + random_count(max_count - 1)
            selection = tuple(random.sample(source, count))
            # not sorted, so we can resend the same content
            # with different system headers
            if selection not in self.sent:
                self.sent.add(selection)
                return selection
        return None

    def select_system(self):
        batch = CONFIG['window']
        oldest = self.oldest_local_mid()
        TRY_INJECT_ACK = 3
        TRY_SAMPLE_BATCH = 50
        TRY_SAMPLE_FULL = 10

        for _ in range(TRY_INJECT_ACK):
            def by_age(m): return ring_difference(m, oldest)
            mids = sorted(self.backlog, key=by_age)

            # first try sending things in first batch
            first = mids[:batch]
            sampled = self.random_sample(first, TRY_SAMPLE_BATCH)
            if sampled is not None:
                return sampled

            # when we found nothing useful in the batch setup,
            # send systems from the full gamut, we want to delay
            # inserting acks
            sampled = self.random_sample(mids, TRY_SAMPLE_FULL)
            if sampled is not None:
                return sampled

            # we failed at making a system, try stiring things up
            self.push_ack()

        assert(not "cannot select a system")
        return tuple()

    def transmit_system(self):
        selection = self.select_system()
        return self.mix_system(selection)

    def transmit(self):
        if len(self.backlog) == 0:
            self.push_ack()

        best_system = self.transmit_system()
        if best_system is not None:
            return best_system

        # we make sure there always is a system to send,
        # but sometimes the encoding in to_address fails,
        # so we might need to try again
        return self.transmit()
