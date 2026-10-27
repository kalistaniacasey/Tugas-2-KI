# Anggota

| Nama | NRP |
|---|---|
| Kalistania Casey Tangkemanda | 5025231302 |
| Nadya Zafira | 5025231310 |

# Key Distribution (KDC) + AES Manual

Implementasi skenario distribusi kunci dengan KDC untuk tiga entitas (KDC, Alice, Bob) di tiga IP berbeda. AES dan KDC ditulis manual tanpa library kriptografi. Hanya memakai Python 3 standard library (socket, threading, json).

## Skenario Key Distribution

| Langkah | Arah | Isi |
|---|---|---|
| 1 | Alice → KDC | `IDa ‖ IDb ‖ N1` (plaintext) |
| 2 | KDC → Alice | `E(Ka, [Ks ‖ IDa ‖ IDb ‖ N1 ‖ E(Kb, [Ks ‖ IDa])])` |
| 3 | Alice → Bob | `E(Kb, [Ks ‖ IDa])` (ticket) |
| 4 | Bob → Alice | `E(Ks, N2)` |
| 5 | Alice → Bob | `E(Ks, f(N2))`, dengan `f(N2) = N2 + 1` |

Setelah langkah 5, Alice dan Bob bertukar pesan dua arah yang dienkripsi AES dengan `Ks`.

- `Ka`, `Kb`: master key milik Alice/Bob yang juga disimpan KDC (diinput saat runtime, tidak di-hardcode).
- `Ks`: session key 16 karakter ASCII acak yang dibuat KDC setiap request.
- `N1`: membuktikan respons KDC baru (anti-replay). `N2`: Bob memastikan Alice benar-benar memegang `Ks`.

> Jika skenario di PPT kelas sedikit berbeda (misalnya bentuk `f(N2)` atau urutan field), ubah bagian berlabel `Langkah X` di `alice.py`, `bob.py`, dan `kdc.py`.

## Struktur File

| File | Isi |
|---|---|
| `aes.py` | AES manual: GF(2^8), S-Box (dibangun dari invers + affine), SubBytes, ShiftRows, MixColumns, AddRoundKey, Key Expansion, mode ECB/CBC, padding PKCS#7, self-test FIPS-197 |
| `kdc.py` | Server KDC: menyimpan master key, membuat `Ks`, membalas langkah 2 |
| `alice.py` | Initiator: langkah 1, 3, 5, lalu chat |
| `bob.py` | Responder (server): langkah 3–5, lalu chat |
| `chat.py` | Kanal chat dua arah terenkripsi + perintah interaktif bersama |
| `net.py` | Kirim/terima JSON via TCP (prefix panjang 4 byte), generator key/nonce |

## Format Data

- Key: ASCII 16/24/32 karakter → AES-128/192/256.
- Plaintext: ASCII.
- Ciphertext: Hex. Mode default CBC, dengan 16 byte pertama sebagai IV. Bisa diganti ke ECB lewat `/mode ecb`.

## Cara Menjalankan (3 Perangkat)

Misal: KDC = `192.168.1.10`, Bob = `192.168.1.30`, Alice = `192.168.1.20`. Semua di jaringan yang sama, dan port 5000 serta 6000 dibuka di firewall.

```bash
# Perangkat KDC
python kdc.py --port 5000
#   Ka = AliceMasterKey16 ; Kb = BobMasterKey1234

# Perangkat Bob
python bob.py --port 6000
#   Kb = BobMasterKey1234

# Perangkat Alice (jalankan terakhir)
python alice.py --kdc 192.168.1.10 --bob 192.168.1.30
#   Ka = AliceMasterKey16
```

Cek IP dengan `ipconfig` (Windows) atau `ip a` (Linux/Mac).

Untuk uji di satu laptop, bisa pakai IP loopback berbeda di Linux: `--host 127.0.0.10` untuk KDC, `--host 127.0.0.30` untuk Bob, lalu `alice.py --kdc 127.0.0.10 --bob 127.0.0.30`. Namun saat demo sebaiknya pakai 3 perangkat sungguhan.

## Perintah Interaktif (tanpa restart)

| Perintah | Tersedia di | Fungsi |
|---|---|---|
| `<teks>` | Alice/Bob | Kirim pesan terenkripsi |
| `/showkey` | Alice/Bob | Tampilkan session key |
| `/setkey <key>` | Alice/Bob | Ganti session key manual (uji key berbeda → dekripsi gagal) |
| `/mode ecb\|cbc` | Alice/Bob | Ganti mode AES |
| `/enc <key> <teks>` | Alice/Bob | Enkripsi lokal |
| `/dec <key> <hex>` | Alice/Bob | Dekripsi lokal |
| `/rekey` | Alice | Ulangi langkah 1–5 dan dapatkan `Ks` baru |
| `/setmaster <key>` | Alice/Bob | Ganti master key sendiri |
| `/keys`, `/setkey <ID> <key>` | KDC | Lihat/ubah master key |

`python aes.py` membuka mode uji AES mandiri (test vector + enkripsi/dekripsi manual).

## Test Case untuk Demo

1. Normal: langkah 1–5 sukses, Alice ↔ Bob saling kirim pesan.
2. Ka salah di Alice: langkah 2 gagal didekripsi.
3. Kb salah di Bob: ticket di langkah 3 ditolak.
4. `/setkey` berbeda di satu sisi: penerima gagal dekripsi (padding invalid).
5. Ganti master key di KDC (`/setkey Alice ...`), lalu `/rekey` di Alice.
6. Pesan panjang (lebih dari 1 blok) dan mode ECB vs CBC: plaintext sama menghasilkan ciphertext berbeda di CBC karena IV acak.

## Wireshark

1. Pilih interface yang terhubung ke jaringan demo (Wi-Fi/Ethernet). Jika uji di satu mesin, pilih Loopback.
2. Filter: `tcp.port == 5000 || tcp.port == 6000`. Bisa dipersempit dengan `ip.addr == 192.168.1.20`.
3. Klik kanan paket → Follow → TCP Stream. Payload JSON akan terbaca:
   - port 5000: `KEY_REQUEST` (ID & N1 plaintext) → `KEY_RESPONSE` (hex)
   - port 6000: `TICKET`, `NONCE`, `NONCE_RESP`, `HANDSHAKE_OK`, lalu `CHAT` (ciphertext hex)
4. Tunjukkan bahwa isi chat hanya terlihat sebagai hex, bukan plaintext.



