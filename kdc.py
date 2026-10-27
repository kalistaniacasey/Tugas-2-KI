import argparse
import socket
import threading

from aes import encrypt_hex, key_from_ascii
from net import send_msg, recv_msg, random_ascii_key, ask_key

master_keys = {}          # ID -> master key (ASCII)
lock = threading.Lock()


def handle_client(conn, addr):
    try:
        req = recv_msg(conn)
        print(f"\n[KDC] Koneksi dari {addr[0]}:{addr[1]}")
        if req.get("type") != "KEY_REQUEST":
            send_msg(conn, {"type": "ERROR", "msg": "Request tidak dikenal"})
            return
        ida, idb, n1 = req["ida"], req["idb"], req["n1"]
        print(f"[KDC] (1) Diterima: IDa={ida}, IDb={idb}, N1={n1}")

        with lock:
            ka, kb = master_keys.get(ida), master_keys.get(idb)
        if ka is None or kb is None:
            send_msg(conn, {"type": "ERROR", "msg": "ID tidak terdaftar di KDC"})
            print("[KDC] ID tidak terdaftar, request ditolak")
            return

        ks = random_ascii_key(16)                       # session key baru
        ticket = encrypt_hex(kb, f"{ks}|{ida}")         # E(Kb, [Ks || IDa])
        inner = f"{ks}|{ida}|{idb}|{n1}|{ticket}"
        payload = encrypt_hex(ka, inner)                # E(Ka, [...])

        print(f"[KDC] Session key Ks dibuat : {ks}")
        print(f"[KDC] Ticket E(Kb,[Ks||IDa]) : {ticket}")
        print(f"[KDC] (2) Dikirim ke {ida}  : {payload}")
        send_msg(conn, {"type": "KEY_RESPONSE", "payload": payload})
    except Exception as e:
        print(f"[KDC] Error: {e}")
    finally:
        conn.close()


def server(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    print(f"[KDC] Listening di {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    print("=== KDC ===  (master key: ASCII 16/24/32 karakter)")
    master_keys["Alice"] = ask_key("Master key Alice (Ka): ")
    master_keys["Bob"] = ask_key("Master key Bob   (Kb): ")

    threading.Thread(target=server, args=(args.host, args.port), daemon=True).start()
    print("Ketik /help untuk daftar perintah.")
    while True:
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        parts = line.split(maxsplit=2)
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "/keys":
            with lock:
                for k, v in master_keys.items():
                    print(f"  {k}: {v}")
        elif cmd == "/setkey" and len(parts) == 3:
            try:
                key_from_ascii(parts[2])
                with lock:
                    master_keys[parts[1]] = parts[2]
                print(f"  Master key {parts[1]} diubah.")
            except ValueError as e:
                print("  ", e)
        elif cmd == "/deluser" and len(parts) == 2:
            with lock:
                master_keys.pop(parts[1], None)
            print(f"  {parts[1]} dihapus.")
        elif cmd == "/quit":
            break
        else:
            print("  /keys                 tampilkan master key\n"
                  "  /setkey <ID> <key>    tambah/ubah master key entitas\n"
                  "  /deluser <ID>         hapus entitas\n"
                  "  /quit                 keluar")


if __name__ == "__main__":
    main()
