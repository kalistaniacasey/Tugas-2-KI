import os


# ---------------------------------------------------------------------------
# 1. Aritmetika di GF(2^8) dengan polinomial x^8 + x^4 + x^3 + x + 1 (0x11B)
# ---------------------------------------------------------------------------
def xtime(a):
    """Perkalian dengan x (=0x02) di GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    """Perkalian dua byte di GF(2^8) (metode shift-and-add)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def ginv(a):
    """Invers perkalian di GF(2^8): a^254 (karena a^255 = 1). Invers 0 didefinisikan 0."""
    if a == 0:
        return 0
    r, p, e = 1, a, 254
    while e:
        if e & 1:
            r = gmul(r, p)
        p = gmul(p, p)
        e >>= 1
    return r


# ---------------------------------------------------------------------------
# 2. Membangun S-Box: invers GF(2^8) lalu transformasi affine (+0x63)
# ---------------------------------------------------------------------------
def _build_sbox():
    sbox, inv_sbox = [0] * 256, [0] * 256
    for x in range(256):
        b = ginv(x)
        s = b
        for i in range(1, 5):  # b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4)
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF
        s ^= 0x63
        sbox[x] = s
        inv_sbox[s] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()

# Round constant: Rcon[i] = x^(i-1) di GF(2^8)
RCON = [0x00, 0x01]
for _ in range(14):
    RCON.append(xtime(RCON[-1]))


# ---------------------------------------------------------------------------
# 3. Transformasi ronde. State = list 16 byte, urutan kolom (column-major):
#    state[4*c + r] = byte baris r, kolom c  (sama dengan urutan byte input)
# ---------------------------------------------------------------------------
def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # baris r digeser ke kiri sebanyak r
    return [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    # baris r digeser ke kanan sebanyak r
    return [s[4 * ((c - r) % 4) + r] for c in range(4) for r in range(4)]


def mix_columns(s):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3,
            a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3,
            a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3),
            gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2),
        ]
    return out


def inv_mix_columns(s):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
            gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
            gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
            gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14),
        ]
    return out


def add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


# ---------------------------------------------------------------------------
# 4. Key Expansion
# ---------------------------------------------------------------------------
def key_expansion(key):
    nk = len(key) // 4          # 4 / 6 / 8 word
    nr = nk + 6                 # 10 / 12 / 14 ronde
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = t[1:] + t[:1]                 # RotWord
            t = [SBOX[b] for b in t]          # SubWord
            t[0] ^= RCON[i // nk]             # XOR Rcon
        elif nk > 6 and i % nk == 4:          # khusus AES-256
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    # gabungkan per 4 word menjadi round key 16 byte
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)], nr


# ---------------------------------------------------------------------------
# 5. Kelas AES (blok tunggal + mode ECB/CBC)
# ---------------------------------------------------------------------------
class AES:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Panjang key harus 16, 24, atau 32 byte")
        self.round_keys, self.nr = key_expansion(key)

    def encrypt_block(self, block: bytes) -> bytes:
        s = add_round_key(list(block), self.round_keys[0])
        for r in range(1, self.nr):
            s = sub_bytes(s)
            s = shift_rows(s)
            s = mix_columns(s)
            s = add_round_key(s, self.round_keys[r])
        s = sub_bytes(s)                      # ronde terakhir tanpa MixColumns
        s = shift_rows(s)
        s = add_round_key(s, self.round_keys[self.nr])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = add_round_key(list(block), self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            s = inv_shift_rows(s)
            s = inv_sub_bytes(s)
            s = add_round_key(s, self.round_keys[r])
            s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, self.round_keys[0])
        return bytes(s)


def pkcs7_pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("Panjang ciphertext tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (kemungkinan key salah)")
    return data[:-n]


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    aes = AES(key)
    p = pkcs7_pad(plaintext)
    return b"".join(aes.encrypt_block(p[i:i + 16]) for i in range(0, len(p), 16))


def decrypt_ecb(key: bytes, ct: bytes) -> bytes:
    aes = AES(key)
    if len(ct) % 16:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte")
    return pkcs7_unpad(b"".join(aes.decrypt_block(ct[i:i + 16]) for i in range(0, len(ct), 16)))


def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes = None) -> bytes:
    """Output = IV (16 byte) || ciphertext."""
    aes = AES(key)
    iv = iv or os.urandom(16)
    p = pkcs7_pad(plaintext)
    prev, out = iv, [iv]
    for i in range(0, len(p), 16):
        blk = bytes(a ^ b for a, b in zip(p[i:i + 16], prev))  # XOR dengan blok sebelumnya
        prev = aes.encrypt_block(blk)
        out.append(prev)
    return b"".join(out)


def decrypt_cbc(key: bytes, data: bytes) -> bytes:
    if len(data) < 32 or len(data) % 16:
        raise ValueError("Panjang ciphertext CBC tidak valid")
    aes = AES(key)
    prev, out = data[:16], []
    for i in range(16, len(data), 16):
        blk = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(aes.decrypt_block(blk), prev)))
        prev = blk
    return pkcs7_unpad(b"".join(out))


# ---------------------------------------------------------------------------
# 6. Helper format: key & plaintext ASCII, ciphertext HEX
# ---------------------------------------------------------------------------
def key_from_ascii(k: str) -> bytes:
    if not k.isascii():
        raise ValueError("Key harus berisi karakter ASCII")
    if len(k) not in (16, 24, 32):
        raise ValueError(f"Key harus 16/24/32 karakter ASCII (sekarang {len(k)})")
    return k.encode("ascii")


def encrypt_hex(key_ascii: str, plaintext_ascii: str, mode: str = "cbc") -> str:
    if not plaintext_ascii.isascii():
        raise ValueError("Plaintext harus berisi karakter ASCII")
    key = key_from_ascii(key_ascii)
    data = plaintext_ascii.encode("ascii")
    ct = encrypt_cbc(key, data) if mode == "cbc" else encrypt_ecb(key, data)
    return ct.hex().upper()


def decrypt_hex(key_ascii: str, ct_hex: str, mode: str = "cbc") -> str:
    key = key_from_ascii(key_ascii)
    ct = bytes.fromhex(ct_hex)
    pt = decrypt_cbc(key, ct) if mode == "cbc" else decrypt_ecb(key, ct)
    return pt.decode("ascii")


# ---------------------------------------------------------------------------
# 7. Self-test dengan test vector resmi FIPS-197 Appendix C
# ---------------------------------------------------------------------------
def self_test():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    vectors = [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    ]
    ok = True
    for k, exp in vectors:
        aes = AES(bytes.fromhex(k))
        ct = aes.encrypt_block(pt)
        good = ct.hex() == exp and aes.decrypt_block(ct) == pt
        ok &= good
        print(f"  AES-{len(k) * 4}: {ct.hex()}  {'OK' if good else 'GAGAL'}")
    return ok


if __name__ == "__main__":
    print("=== AES Manual - Mode Interaktif ===")
    print("Test vector FIPS-197:")
    self_test()
    mode = "cbc"
    while True:
        print(f"\n[mode={mode.upper()}]  1) Enkripsi  2) Dekripsi  3) Ganti mode  4) Keluar")
        pil = input("Pilih: ").strip()
        try:
            if pil == "1":
                k = input("Key (ASCII 16/24/32 karakter): ")
                p = input("Plaintext (ASCII): ")
                print("Ciphertext (HEX):", encrypt_hex(k, p, mode))
            elif pil == "2":
                k = input("Key (ASCII 16/24/32 karakter): ")
                c = input("Ciphertext (HEX): ").strip()
                print("Plaintext (ASCII):", decrypt_hex(k, c, mode))
            elif pil == "3":
                mode = "ecb" if mode == "cbc" else "cbc"
            elif pil == "4":
                break
        except ValueError as e:
            print("Error:", e)
