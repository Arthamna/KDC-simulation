import secrets
import socket
import threading

from kdc.protocol import ascii_key, open_sealed, seal
from network.transport import connect, receive_message, send_message


class AliceNode:
    def __init__(self, host: str, master_key: str, on_message=None):
        ascii_key(master_key)
        self.host = host
        self.master_key = master_key
        self.on_message = on_message or (lambda text: print(f'\n[Bob] {text}'))
        self.peer = None
        self.session_key = None

    def handshake(self, kdc_host: str, kdc_port: int, bob_host: str, bob_port: int):
        self.close_session()
        n1 = secrets.token_hex(8)
        with connect(kdc_host, kdc_port, self.host) as kdc:
            send_message(kdc, {'type': 'KDC_REQUEST', 'alice': 'Alice', 'bob': 'Bob', 'n1': n1})
            reply = receive_message(kdc)
        if reply.get('type') != 'KDC_REPLY':
            raise ValueError(reply.get('reason', 'KDC request failed'))
        payload = open_sealed(reply['alice_part'], self.master_key)
        if (payload.get('alice'), payload.get('bob'), payload.get('n1')) != ('Alice', 'Bob', n1):
            raise ValueError('KDC response identity/nonce mismatch')
        ks = payload['ks']
        ascii_key(ks)
        print('[Alice] Steps 1-2 completed: session key received')

        bob = connect(bob_host, bob_port, self.host)
        try:
            send_message(bob, {'type': 'TICKET', 'ticket': reply['ticket']})
            challenge = receive_message(bob)
            if challenge.get('type') != 'CHALLENGE':
                raise ValueError('Expected CHALLENGE')
            nonce = open_sealed(challenge['data'], ks)['n2']
            if not isinstance(nonce, int) or nonce < 1:
                raise ValueError('Invalid N2')
            send_message(bob, {'type': 'CHALLENGE_REPLY', 'data': seal({'n2_minus_one': nonce - 1}, ks)})
            result = receive_message(bob)
            if result.get('type') != 'AUTH_OK':
                raise ValueError('Bob authentication rejected')
            bob.settimeout(None)
        except Exception:
            bob.close()
            raise

        self.peer, self.session_key = bob, ks
        threading.Thread(target=self._receive_loop, args=(bob, ks), daemon=True).start()
        print('[Alice] Steps 3-5 completed: authenticated session ready')

    def _receive_loop(self, peer, ks):
        try:
            while True:
                incoming = receive_message(peer)
                if incoming.get('type') != 'CHAT':
                    raise ValueError('Expected CHAT')
                text = open_sealed(incoming['data'], ks)['text']
                text.encode('ascii')
                print(f"\n[Alice RX] IV={incoming['data']['iv']} CIPHER={incoming['data']['ciphertext']}")
                self.on_message(text)
        except (OSError, EOFError, ValueError, KeyError, UnicodeError) as exc:
            print(f'[Alice] Connection ended: {exc}')
        finally:
            if self.peer is peer:
                self.peer, self.session_key = None, None
            peer.close()

    def send_chat(self, text: str):
        text.encode('ascii')
        if self.peer is None:
            raise ValueError('No authenticated session')
        envelope = seal({'text': text}, self.session_key)
        send_message(self.peer, {'type': 'CHAT', 'data': envelope})
        print(f"[Alice TX] IV={envelope['iv']} CIPHER={envelope['ciphertext']}")

    def update_key(self, key: str):
        ascii_key(key)
        self.close_session()
        self.master_key = key
        print('[Alice] Master key updated; synchronize with KDC.')

    def close_session(self):
        peer = self.peer
        self.peer, self.session_key = None, None
        if peer:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()

def main():
    parser = argparse.ArgumentParser(description='Alice AES-CBC chat')
    parser.add_argument('--host', required=True, help='Alice machine IP address (source bind)')
    parser.add_argument('--kdc-host', required=True)
    parser.add_argument('--kdc-port', type=int, default=9000)
    parser.add_argument('--bob-host', required=True)
    parser.add_argument('--bob-port', type=int, default=9001)
    args = parser.parse_args()

    alice = AliceNode(args.host, input('Alice master key (16 ASCII chars): '))
    try:
        while True:
            print('\nAlice: 1=Change key  2=Change endpoints  3=Start/Rekey session  4=Send chat  5=End session  0=Exit')
            choice = input('> ').strip()
            if choice == '0':
                break
            try:
                if choice == '1':
                    alice.update_key(input('New Alice master key: '))
                elif choice == '2':
                    args.kdc_host = input(f'KDC IP [{args.kdc_host}]: ') or args.kdc_host
                    args.bob_host = input(f'Bob IP [{args.bob_host}]: ') or args.bob_host
                elif choice == '3':
                    alice.handshake(args.kdc_host, args.kdc_port, args.bob_host, args.bob_port)
                elif choice == '4':
                    alice.send_chat(input('Message (ASCII): '))
                elif choice == '5':
                    alice.close_session()
            except (OSError, ValueError, KeyError, EOFError, UnicodeError) as exc:
                print(f'Error: {exc}')
    finally:
        alice.close_session()


if __name__ == '__main__':
    main()