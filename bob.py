import argparse
import socket
import threading

from aes import encrypt_hex, decrypt_hex, key_from_ascii
from chat import SecureChannel, HELP, handle_common
from net import send_msg, recv_msg, random_nonce, ask_key

state = {"kb": None, "channel": None, "mode": "cbc", "id": "Bob"}


def handshake(conn, addr):
    me = state["id"]
    print(f"\n[{me}] Koneksi masuk dari {addr[0]}:{addr[1]}")
    try:
        msg = recv_msg(conn)
        if msg.get("type") != "TICKET":
            raise RuntimeError("Pesan pertama bukan ticket")
        print(f"[{me}] (3) Ticket diterima: {msg['ticket']}")
        try:
            ks, ida = decrypt_hex(state["kb"], msg["ticket"]).split("|", 1)
        except Exception:
            send_msg(conn, {"type": "ERROR", "msg": "Ticket tidak bisa didekripsi dengan Kb"})
            raise RuntimeError("Ticket tidak bisa didekripsi (Kb tidak cocok dengan KDC)")
        print(f"[{me}]     Didekripsi: Ks={ks}, IDa={ida}")

        n2 = random_nonce()
        c4 = encrypt_hex(ks, str(n2))
        print(f"[{me}] (4) Kirim E(Ks,N2) dengan N2={n2}: {c4}")
        send_msg(conn, {"type": "NONCE", "payload": c4})

        msg = recv_msg(conn)
        print(f"[{me}] (5) Diterima E(Ks,f(N2)): {msg['payload']}")
        resp = int(decrypt_hex(ks, msg["payload"]))
        if resp != n2 + 1:
            send_msg(conn, {"type": "ERROR", "msg": "f(N2) salah"})
            raise RuntimeError(f"f(N2) salah: {resp} != {n2 + 1}")
        print(f"[{me}]     f(N2)={resp} benar -> {ida} terautentikasi")
        send_msg(conn, {"type": "HANDSHAKE_OK"})

        if state["channel"]:
            state["channel"].close()
        ch = SecureChannel(conn, me, ida, ks, state["mode"])
        state["channel"] = ch
        ch.start()
        print(f"[{me}] Key distribution selesai. Session key Ks = {ks}\n")
    except Exception as e:
        print(f"[{me}] Handshake gagal: {e}")
        conn.close()


def server(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    print(f"[{state['id']}] Listening di {host}:{port}, menunggu Alice...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handshake, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--id", default="Bob")
    args = ap.parse_args()
    state["id"] = args.id

    print(f"=== {args.id} ===")
    state["kb"] = ask_key(f"Master key {args.id} (Kb, harus sama dengan di KDC): ")
    threading.Thread(target=server, args=(args.host, args.port), daemon=True).start()
    print("Ketik pesan untuk dikirim, atau /help.")

    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        if not line.strip():
            continue
        ch = state["channel"]
        if line.startswith("/"):
            cmd, _, arg = line.strip().partition(" ")
            if cmd == "/quit":
                break
            elif cmd == "/setmaster":
                try:
                    key_from_ascii(arg)
                    state["kb"] = arg
                    print("  Master key Kb diubah.")
                except ValueError as e:
                    print("  ", e)
            elif not handle_common(cmd, arg, ch, state):
                print(HELP + "\n  /setmaster <key>     ganti master key Kb\n  /quit")
        elif ch and ch.alive:
            try:
                ch.send(line)
            except Exception as e:
                print("  Gagal kirim:", e)
        else:
            print("  Belum ada sesi dengan Alice.")
    if state["channel"]:
        state["channel"].close()


if __name__ == "__main__":
    main()
