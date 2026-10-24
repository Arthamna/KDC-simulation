import unittest

from kdc.protocol import open_sealed, seal
from kdc.server import KDCServer
from network.transport import connect, receive_message, send_message

KA = 'AliceMasterKey01'
KB = 'BobMasterKey0001'


class KDCTests(unittest.TestCase):
    def setUp(self):
        self.kdc = KDCServer('127.0.0.1', 0, KA, KB)
        self.kdc.start()

    def tearDown(self):
        self.kdc.stop()

    def request(self):
        with connect('127.0.0.1', self.kdc.port, '127.0.0.1') as peer:
            send_message(peer, {'type': 'KDC_REQUEST', 'alice': 'Alice', 'bob': 'Bob', 'n1': 'abc123'})
            return receive_message(peer)

    def test_session_key_and_ticket(self):
        reply = self.request()
        self.assertEqual(reply['type'], 'KDC_REPLY')
        alice = open_sealed(reply['alice_part'], KA)
        bob = open_sealed(reply['ticket'], KB)
        self.assertEqual(alice['ks'], bob['ks'])
        self.assertEqual(alice['n1'], 'abc123')
        self.assertEqual(alice['alice'], 'Alice')
        self.assertEqual(alice['bob'], 'Bob')
        self.assertEqual(bob['alice'], 'Alice')
        self.assertEqual(len(alice['ks']), 16)

    def test_keys_are_unique_and_encryptions_change(self):
        first, second = self.request(), self.request()
        self.assertNotEqual(open_sealed(first['alice_part'], KA)['ks'],
                            open_sealed(second['alice_part'], KA)['ks'])
        self.assertNotEqual(first['alice_part']['iv'], second['alice_part']['iv'])


if __name__ == '__main__':
    unittest.main()