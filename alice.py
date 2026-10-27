import argparse
import socket

from aes import encrypt_hex, decrypt_hex, key_from_ascii
from chat import SecureChannel, HELP, handle_common
from net import send_msg, recv_msg, random_nonce, ask_key


def key_distribution(cfg, ka):
    me, peer = cfg.id, cfg.peer

    n1 = random_nonce()
    with socket.create_connection((cfg.kdc, cfg.kdc_port), timeout=10) as s:
        print(f"[{me}] (1) Kirim ke KDC: IDa={me}, IDb={peer}, N1={n1}")
        send_msg(s, {"type": "KEY_REQUEST", "ida": me, "idb": peer, "n1": n1})
        resp = recv_msg(s)
    if resp.get("type") != "KEY_RESPONSE":
        raise RuntimeError(f"KDC menolak: {resp.get('msg')}")

    print(f"[{me}] (2) Diterima dari KDC: {resp['payload']}")
    try:
        inner = decrypt_hex(ka, resp["payload"])
    except Exception:
        raise RuntimeError("Gagal dekripsi respon KDC (Ka tidak cocok dengan KDC)")
    ks, ida, idb, n1_resp, ticket = inner.split("|", 4)
    print(f"[{me}]     Didekripsi: Ks={ks}, IDa={ida}, IDb={idb}, N1={n1_resp}")
    if ida != me or idb != peer or int(n1_resp) != n1:
        raise RuntimeError("Verifikasi gagal: ID / N1 tidak cocok (kemungkinan replay)")
    print(f"[{me}]     N1 cocok -> respon KDC asli dan baru (fresh)")

    sock = socket.create_connection((cfg.bob, cfg.bob_port), timeout=10)
    sock.settimeout(None)
    print(f"[{me}] (3) Kirim ticket ke {peer}: {ticket}")
    send_msg(sock, {"type": "TICKET", "ticket": ticket})

    msg = recv_msg(sock)
    if msg.get("type") != "NONCE":
        sock.close()
        raise RuntimeError(f"{peer} menolak ticket: {msg.get('msg')}")
    n2 = int(decrypt_hex(ks, msg["payload"]))
    print(f"[{me}] (4) Diterima E(Ks,N2): {msg['payload']}  -> N2={n2}")

    f_n2 = encrypt_hex(ks, str(n2 + 1))
    print(f"[{me}] (5) Kirim E(Ks,f(N2)) dengan f(N2)={n2 + 1}: {f_n2}")
    send_msg(sock, {"type": "NONCE_RESP", "payload": f_n2})

    ack = recv_msg(sock)
    if ack.get("type") != "HANDSHAKE_OK":
        sock.close()
        raise RuntimeError(f"Autentikasi gagal: {ack.get('msg')}")
    print(f"[{me}] Key distribution selesai. Session key Ks = {ks}\n")
    return sock, ks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kdc", required=True, help="IP KDC")
    ap.add_argument("--kdc-port", type=int, default=5000)
    ap.add_argument("--bob", required=True, help="IP Bob")
    ap.add_argument("--bob-port", type=int, default=6000)
    ap.add_argument("--id", default="Alice")
    ap.add_argument("--peer", default="Bob")
    cfg = ap.parse_args()

    print(f"=== {cfg.id} ===")
    ka = ask_key(f"Master key {cfg.id} (Ka, harus sama dengan di KDC): ")
    channel, state = None, {"mode": "cbc"}

    def connect():
        nonlocal channel
        if channel:
            channel.close()
        try:
            sock, ks = key_distribution(cfg, ka)
            channel = SecureChannel(sock, cfg.id, cfg.peer, ks, state["mode"])
            channel.start()
        except Exception as e:
            channel = None
            print(f"[{cfg.id}] Key distribution gagal: {e}")

    connect()
    print("Ketik pesan untuk dikirim, atau /help.")
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        if not line.strip():
            continue
        if line.startswith("/"):
            cmd, _, arg = line.strip().partition(" ")
            if cmd == "/quit":
                break
            elif cmd == "/rekey":
                connect()
            elif cmd == "/setmaster":
                try:
                    key_from_ascii(arg)
                    ka = arg
                    print("  Master key Ka diubah (berlaku saat /rekey).")
                except ValueError as e:
                    print("  ", e)
            elif not handle_common(cmd, arg, channel, state):
                print(HELP + "\n  /rekey               jalankan ulang langkah 1-5 (Ks baru)"
                      "\n  /setmaster <key>     ganti master key Ka\n  /quit")
        elif channel and channel.alive:
            try:
                channel.send(line)
            except Exception as e:
                print("  Gagal kirim:", e)
        else:
            print("  Belum terhubung. Gunakan /rekey.")
    if channel:
        channel.close()


if __name__ == "__main__":
    main()
