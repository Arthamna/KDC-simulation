import argparse
import secrets
import threading

from kdc.protocol import ascii_key, new_session_key, seal
from network.transport import listen, receive_message, send_message


class KDCServer:
    def __init__(self, host: str, port: int, alice_key: str, bob_key: str):
        ascii_key(alice_key)
        ascii_key(bob_key)
        self.host, self.port = host, port
        self.keys = {'Alice': alice_key, 'Bob': bob_key}
        self.lock = threading.Lock()
        self.server = None
        self.active = True

    def start(self):
        self.server = listen(self.host, self.port)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f'[KDC] Listening on {self.host}:{self.port}')

    def _accept_loop(self):
        while self.active:
            try:
                client, address = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client, address), daemon=True).start()

    def _handle(self, client, address):
        with client:
            try:
                request = receive_message(client)
                if request.get('type') != 'KDC_REQUEST' or request.get('alice') != 'Alice' or request.get('bob') != 'Bob':
                    raise ValueError('Invalid KDC request')
                n1 = request['n1']
                if not isinstance(n1, str) or not n1 or len(n1) > 128:
                    raise ValueError('Invalid N1')
                with self.lock:
                    ka, kb = self.keys['Alice'], self.keys['Bob']
                ks = new_session_key()
                alice_part = seal({'ks': ks, 'alice': 'Alice', 'bob': 'Bob', 'n1': n1}, ka)
                ticket = seal({'ks': ks, 'alice': 'Alice'}, kb)
                send_message(client, {'type': 'KDC_REPLY', 'alice_part': alice_part, 'ticket': ticket})
                print(f'[KDC] Issued a session key for Alice/Bob ({address[0]})')
            except (ValueError, KeyError, EOFError, UnicodeError) as exc:
                send_message(client, {'type': 'ERROR', 'reason': str(exc)})

    def update_key(self, user: str, key: str):
        ascii_key(key)
        with self.lock:
            self.keys[user] = key
        print(f'[KDC] {user} master key updated; synchronize with {user}.')

    def stop(self):
        self.active = False
        if self.server:
            self.server.close()