import json
import secrets
import string
import struct


def send_msg(sock, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup oleh peer")
        buf += chunk
    return buf


def recv_msg(sock) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    return json.loads(_recv_exact(sock, length).decode("utf-8"))


def random_ascii_key(n=16) -> str:
    """Session key acak berupa n karakter ASCII (huruf + angka)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def random_nonce() -> int:
    return secrets.randbelow(10**9)


def ask_key(prompt: str) -> str:
    from aes import key_from_ascii
    while True:
        k = input(prompt)
        try:
            key_from_ascii(k)
            return k
        except ValueError as e:
            print("  ", e)
