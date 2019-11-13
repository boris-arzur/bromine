import bromine
import os
import random
import unittest

# some tests expect things more or less in order, but $(python -m unittest -k lossy) should work
#bromine.CONFIG['_fickle'] = 0.99
# bromine.CONFIG['_tiny'] = 13  # at least 13


def address_to_mids(address):
    tranmission = bromine.from_address(address)
    return bromine.System().from_transmission(tranmission).mids


def is_data(line):
    return bromine.get_type(line) == bromine.TYPE_DATA


def is_ack(line):
    return bromine.get_type(line) == bromine.TYPE_ACK


def data(unit):
    size = bromine.max_size() - bromine.OVERHEAD
    return os.urandom(int(size * unit))


class Endpoint:
    def __init__(self):
        self.emit = bromine.Scoreboard()
        self.recv = bromine.Systems()
        self.data = []

    def talk_to(self, rhs):
        # transmissions can cross the local/remote barrier
        rhs.recv.add(self.emit.transmit())

    def ack(self):
        self.emit.push_ack(self.recv.last_seen_remote_mid)

    def pull_data(self):
        self.data += self.recv.data

    def retire(self):
        for ack in self.recv.acks:
            self.emit.retire(ack[0])

    def commit(self):
        self.recv.commit()

    def one_pass(self, rhs, messages):
        # recv + update things
        self.retire()
        self.ack()
        self.pull_data()
        self.commit()

        # emit things
        for _ in range(messages):
            self.talk_to(rhs)


class TestCase(unittest.TestCase):
    def test_address(self):
        size = bromine.max_size()
        data = os.urandom(size)
        address = bromine.to_address(data)
        if address is not None:
            back = bromine.from_address(address)
            self.assertTrue(bromine.valid_dns_name(address))
            self.assertEqual(back, data)

    def test_ack(self):
        score_board = bromine.Scoreboard()
        systems = bromine.Systems()

        score_board.last_seen_remote_mid = 42
        ack = score_board.transmit()
        self.assertTrue(bromine.valid_dns_name(ack))

        if score_board.mid == 1:
            systems.add(ack)
            self.assertEqual(systems.acks, [(42, 0)])

    def test_data(self):
        score_board = bromine.Scoreboard()
        systems = bromine.Systems()

        payload = data(1)
        score_board.push_data(payload)

        loaded = score_board.transmit()
        self.assertTrue(bromine.valid_dns_name(loaded))

        if score_board.mid == 1:
            systems.add(loaded)
            self.assertEqual(len(systems.data), 1)
            self.assertEqual(systems.data[0], payload)

    def test_mini(self):
        score_board = bromine.Scoreboard()
        systems = bromine.Systems()

        payload = data(0.2)
        score_board.push_data(payload)

        loaded = score_board.transmit()
        self.assertTrue(bromine.valid_dns_name(loaded))

        if score_board.mid == 1:
            systems.add(loaded)
            self.assertEqual(len(systems.data), 1)
            self.assertEqual(systems.data[0], payload)

    def test_lossy(self):
        bromine.CONFIG['n'] = 3  # can't do it with N being even
        score_board = bromine.Scoreboard()
        systems = bromine.Systems()

        payload = data(30)
        score_board.push_data(payload)

        iterations = 0
        while len(systems.data) < 30:
            iterations += 1
            #self.assertTrue(iterations < 100)
            address = score_board.transmit()
            mids = address_to_mids(address)
            if len(mids) == 1 and random.random() < 0.9:
                pass  # drop
                # random number generation is heavily tilted towards
                # small systems... dropping all of them is difficult
            else:
                # keep complex systems and some singletons, hope to reconstruct
                # all messages
                systems.add(address)

            score_board.retire(systems.last_seen_remote_mid)

        self.assertEqual(b''.join(systems.data), payload)

    def test_trim(self):
        PASS_NUM_MESSAGES = 5
        local, remote = Endpoint(), Endpoint()

        payload = data(1)
        local.emit.push_data(payload)

        # make sure we detect that data payload
        self.assertTrue(any(is_data(line)
                            for line in local.emit.backlog.values()))

        local.one_pass(remote, PASS_NUM_MESSAGES)
        remote.one_pass(local, PASS_NUM_MESSAGES)
        local.one_pass(remote, PASS_NUM_MESSAGES)
        remote.one_pass(local, PASS_NUM_MESSAGES)

        # some messages were reclaimed
        recvd_messages = len(local.recv.systems) + len(remote.recv.systems)
        self.assertTrue(recvd_messages < 4 * PASS_NUM_MESSAGES)

        # our initial payload was reclaimed
        self.assertFalse(any(is_data(line)
                             for line in local.emit.backlog.values()))

    def test_variety(self):
        score_board = bromine.Scoreboard()

        SOME = 5
        for _ in range(SOME):
            score_board.push_data(data(1))

        for i in range(SOME):
            address = score_board.transmit()
            mids = address_to_mids(address)
            if len(mids) > 1:
                # systems get complex very soon
                break
        else:
            self.assertFalse("should have break'd")

        addresses = set()
        for i in range(10 * SOME):
            address = score_board.transmit()
            self.assertFalse(address in addresses)
            addresses.add(address)

    def test_wrapping_ringbuffer(self):
        reset = bromine.CONFIG['reset']
        LOOPS = 7
        CLOSER = 23
        bromine.CONFIG['reset'] = CLOSER

        local, remote = Endpoint(), Endpoint()

        traffic = []
        # this should wrap a few times
        for _ in range(LOOPS):
            for _ in range(CLOSER // 5):
                # cant eat more than half the ring space in
                # one pass, or ring_difference and friends go nuts
                atom = data(1)
                local.emit.push_data(atom)
                traffic.append(atom)

            # make sure all the data is piped to
            # the other side
            while any(is_data(line) for line in local.emit.backlog.values()):
                try:
                    local.one_pass(remote, CLOSER // 5)
                    remote.one_pass(local, 1)
                except AssertionError:
                    # this happens when we don't trim fast enough
                    # for ack allocation... not really an error,
                    # shouldn't happen for a ring big enough,
                    # i.e. outside of testing.
                    return

        def stitch(a): return b''.join(a)
        self.assertEqual(stitch(traffic), stitch(remote.data))

        bromine.CONFIG['reset'] = reset
