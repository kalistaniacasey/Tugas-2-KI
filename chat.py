"""
Kanal komunikasi aman Alice <-> Bob setelah langkah (5).
Setiap pesan dienkripsi AES dengan session key Ks; ciphertext dikirim dalam HEX.
Kedua pihak bisa mengirim dan menerima secara bersamaan (thread penerima terpisah).
"""
import threading

from aes import encrypt_hex, decrypt_hex, key_from_ascii
from net import send_msg, recv_msg


class SecureChannel:
    def __init__(self, sock, me, peer, session_key, mode="cbc"):
        self.sock, self.me, self.peer = sock, me, peer
        self.key, self.mode = session_key, mode
        self.alive = True

    def start(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        while self.alive:
            try:
                msg = recv_msg(self.sock)
            except Exception:
                if self.alive:
                    print(f"\n[{self.me}] Koneksi dengan {self.peer} terputus.")
                self.alive = False
                break
            if msg.get("type") != "CHAT":
                continue
            ct, mode = msg["ct"], msg.get("mode", "cbc")
            print(f"\n[{self.me}] <== Ciphertext dari {self.peer} ({mode.upper()}): {ct}")
            try:
                pt = decrypt_hex(self.key, ct, mode)
                print(f"[{self.me}]     Plaintext : {pt}")
            except Exception as e:
                print(f"[{self.me}]     Gagal dekripsi: {e}")

    def send(self, text):
        ct = encrypt_hex(self.key, text, self.mode)
        send_msg(self.sock, {"type": "CHAT", "mode": self.mode, "ct": ct})
        print(f"[{self.me}] ==> Ciphertext ke {self.peer} ({self.mode.upper()}): {ct}")

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except Exception:
            pass


HELP = """  <teks>               kirim pesan terenkripsi
  /showkey             tampilkan session key aktif
  /setkey <key>        ganti session key manual (uji key salah/beda)
  /mode ecb|cbc        ganti mode AES pengiriman
  /enc <key> <teks>    enkripsi lokal (tanpa kirim)
  /dec <key> <hex>     dekripsi lokal"""


def handle_common(cmd, arg, channel, mode_holder):
    """Perintah yang sama untuk Alice & Bob. Return True bila perintah dikenali."""
    if cmd == "/showkey":
        print("  Session key:", channel.key if channel else "(belum ada)")
    elif cmd == "/setkey":
        try:
            key_from_ascii(arg)
            if channel:
                channel.key = arg
            print("  Session key diubah ->", arg)
        except ValueError as e:
            print("  ", e)
    elif cmd == "/mode":
        if arg in ("ecb", "cbc"):
            mode_holder["mode"] = arg
            if channel:
                channel.mode = arg
            print("  Mode ->", arg.upper())
        else:
            print("  Gunakan /mode ecb atau /mode cbc")
    elif cmd in ("/enc", "/dec"):
        try:
            k, data = arg.split(" ", 1)
            m = mode_holder["mode"]
            out = encrypt_hex(k, data, m) if cmd == "/enc" else decrypt_hex(k, data.strip(), m)
            print("  Hasil:", out)
        except ValueError as e:
            print("  Error:", e)
    else:
        return False
    return True
