import json
import socket


def connect(host: str, port: int, local_ip: str) -> socket.socket:
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.settimeout(10)
    try:
        peer.bind((local_ip, 0))
        peer.connect((host, port))
    except OSError:
        peer.close()
        raise
    return peer


def listen(host: str, port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    return server


def send_message(peer: socket.socket, message: dict) -> None:
    payload = json.dumps(message, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    peer.sendall(len(payload).to_bytes(4, 'big') + payload)


def _read_exact(peer: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = peer.recv(size - len(chunks))
        if not piece:
            raise EOFError('Connection closed')
        chunks.extend(piece)
    return bytes(chunks)


def receive_message(peer: socket.socket) -> dict:
    size = int.from_bytes(_read_exact(peer, 4), 'big')
    if size < 1 :
        raise ValueError('Invalid message size')
    message = json.loads(_read_exact(peer, size).decode('ascii'))
    if not isinstance(message, dict):
        raise ValueError('Expected a JSON object')
    return message