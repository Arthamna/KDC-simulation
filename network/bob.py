import argparse
import secrets
import socket
import threading

from kdc.protocol import ascii_key, open_sealed, seal
from network.transport import listen, receive_message, send_message


class BobNode:
    def __init__(self, host: str, port: int, master_key: str, on_message=None):
        ascii_key(master_key)
        self.host, self.port = host, port
        self.master_key = master_key
        self.on_message = on_message or (lambda text: print(f'\n[Alice] {text}'))
        self.lock = threading.Lock()
        self.peer = None
        self.session_key = None
        self.server = None
        self.running = True

    def start(self):
        self.server = listen(self.host, self.port)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f'[Bob] Listening on {self.host}:{self.port}')

    def _accept_loop(self):
        while self.running:
            try:
                client, address = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client, address), daemon=True).start()

    def _handle(self, client, address):
        with client:
            try:
                client.settimeout(10)
                message = receive_message(client)
                if message.get('type') != 'TICKET':
                    raise ValueError('Expected TICKET')
                with self.lock:
                    kb = self.master_key
                ticket = open_sealed(message['ticket'], kb)
                if ticket.get('alice') != 'Alice':
                    raise ValueError('Invalid Alice identity')
                ks = ticket['ks']
                ascii_key(ks)

                n2 = secrets.randbelow(2**32 - 1) + 1
                send_message(client, {'type': 'CHALLENGE', 'data': seal({'n2': n2}, ks)})
                response = receive_message(client)
                if response.get('type') != 'CHALLENGE_REPLY':
                    raise ValueError('Missing challenge response')
                answer = open_sealed(response['data'], ks)
                if answer.get('n2_minus_one') != n2 - 1:
                    raise ValueError('Authentication failed')

                with self.lock:
                    old = self.peer
                    self.peer, self.session_key = client, ks
                if old:
                    try:
                        old.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    old.close()
                send_message(client, {'type': 'AUTH_OK'})
                client.settimeout(None)
                print(f'[Bob] Authentication successful from {address[0]}')

                while True:
                    incoming = receive_message(client)
                    if incoming.get('type') != 'CHAT':
                        raise ValueError('Expected CHAT')
                    text = open_sealed(incoming['data'], ks)['text']
                    text.encode('ascii')
                    print(f"\n[Bob RX] IV={incoming['data']['iv']} CIPHER={incoming['data']['ciphertext']}")
                    self.on_message(text)
            except (OSError, EOFError, ValueError, KeyError, UnicodeError) as exc:
                print(f'[Bob] Connection ended: {exc}')
            finally:
                with self.lock:
                    if self.peer is client:
                        self.peer, self.session_key = None, None

    def send_chat(self, text: str):
        text.encode('ascii')
        with self.lock:
            peer, ks = self.peer, self.session_key
        if peer is None:
            raise ValueError('No authenticated session')
        envelope = seal({'text': text}, ks)
        send_message(peer, {'type': 'CHAT', 'data': envelope})
        print(f"[Bob TX] IV={envelope['iv']} CIPHER={envelope['ciphertext']}")

    def update_key(self, key: str):
        ascii_key(key)
        with self.lock:
            self.master_key = key
            old = self.peer
            self.peer, self.session_key = None, None
        if old:
            try:
                old.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            old.close()
        print('[Bob] Master key updated; synchronize with KDC.')

    def close_session(self):
        with self.lock:
            peer = self.peer
            self.peer, self.session_key = None, None
        if peer:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()

    def stop(self):
        self.running = False
        self.close_session()
        if self.server:
            self.server.close()