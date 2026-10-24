import threading
import unittest

from kdc.protocol import open_sealed, seal
from kdc.server import KDCServer
from network.alice import AliceNode
from network.bob import BobNode
from network.transport import connect, receive_message, send_message

KA = 'AliceMasterKey01'
KB = 'BobMasterKey0001'


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.received_alice, self.received_bob = [], []
        self.alice_event, self.bob_event = threading.Event(), threading.Event()

        def from_bob(text):
            self.received_alice.append(text)
            self.alice_event.set()

        def from_alice(text):
            self.received_bob.append(text)
            self.bob_event.set()

        self.kdc = KDCServer('127.0.0.1', 0, KA, KB)
        self.kdc.start()
        self.bob = BobNode('127.0.0.2', 0, KB, on_message=from_alice)
        self.bob.start()
        self.alice = AliceNode('127.0.0.3', KA, on_message=from_bob)

    def tearDown(self):
        self.alice.close_session()
        self.bob.stop()
        self.kdc.stop()

    def test_bidirectional_chat_and_rekey(self):
        self.alice.handshake('127.0.0.1', self.kdc.port, '127.0.0.2', self.bob.port)
        first_key = self.alice.session_key
        self.assertEqual(first_key, self.bob.session_key)
        self.alice.send_chat('Hello Bob')
        self.assertTrue(self.bob_event.wait(3))
        self.assertEqual(self.received_bob[-1], 'Hello Bob')
        self.bob.send_chat('Hello Alice')
        self.assertTrue(self.alice_event.wait(3))
        self.assertEqual(self.received_alice[-1], 'Hello Alice')
        self.alice.handshake('127.0.0.1', self.kdc.port, '127.0.0.2', self.bob.port)
        self.assertNotEqual(self.alice.session_key, first_key)
        self.assertEqual(self.alice.session_key, self.bob.session_key)

    def test_master_keys_can_change_without_restart(self):
        new_ka, new_kb = 'NewAliceMaster01', 'NewBobMaster0001'
        self.kdc.update_key('Alice', new_ka)
        self.kdc.update_key('Bob', new_kb)
        self.alice.update_key(new_ka)
        self.bob.update_key(new_kb)
        self.alice.handshake('127.0.0.1', self.kdc.port, '127.0.0.2', self.bob.port)
        self.assertEqual(self.alice.session_key, self.bob.session_key)

    def test_wrong_challenge_answer_is_rejected(self):
        with connect('127.0.0.1', self.kdc.port, '127.0.0.3') as peer:
            send_message(peer, {'type': 'KDC_REQUEST', 'alice': 'Alice', 'bob': 'Bob', 'n1': 'hello'})
            reply = receive_message(peer)
        ks = open_sealed(reply['alice_part'], KA)['ks']
        with connect('127.0.0.2', self.bob.port, '127.0.0.3') as peer:
            send_message(peer, {'type': 'TICKET', 'ticket': reply['ticket']})
            challenge = receive_message(peer)
            self.assertEqual(challenge['type'], 'CHALLENGE')
            n2 = open_sealed(challenge['data'], ks)['n2']
            send_message(peer, {'type': 'CHALLENGE_REPLY', 'data': seal({'n2_minus_one': n2}, ks)})
            with self.assertRaises(EOFError):
                receive_message(peer)
        self.assertIsNone(self.bob.session_key)


if __name__ == '__main__':
    unittest.main()