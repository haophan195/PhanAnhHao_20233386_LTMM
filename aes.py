"""
AES-128 - cai dat tu dau, in trang thai (state) sau tung phep bien doi.

Cach dung:
    python aes.py --key 000102030405060708090a0b0c0d0e0f --pt 00112233445566778899aabbccddeeff
    python aes.py --key 00 --pt 0000000000000011            # input ngan duoc them 0 vao ben trai
    python aes.py --key ... --ct ... --decrypt

Trang thai la 16 byte xep THEO COT (column-major) nhu FIPS-197:
    state[r][c] = in[r + 4*c]
Ta luu phang thanh list 16 byte: chi so i = r + 4*c.
Dinh dang in giong Appendix B/C cua FIPS-197 (round[i].start, .s_box, .s_row, .m_col, .k_sch).
"""
import argparse

# ----------------------------------------------------------------------------
# 1. SO HOC TRUONG GF(2^8) VOI DA THUC BAT KHA QUY m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
#    Luu y: AES dung 0x11B. Da thuc trong bai tap tim nghich dao o GF(2^8) cua co (x^8+x^4+x^3+x^2+x+1 = 0x11F) la bai khac.
# ----------------------------------------------------------------------------
MOD = 0x11B


def gmul(a, b):
    """Nhan hai phan tu trong GF(2^8): nhan da thuc roi lay du cho m(x)."""
    res = 0
    while b:
        if b & 1:
            res ^= a                 # cong (xor) khi bit thap cua b la 1
        a <<= 1                      # a = a * x
        if a & 0x100:                # bac 8 -> giam bang m(x)
            a ^= MOD
        b >>= 1
    return res


def ginv(a):
    """Nghich dao nhan trong GF(2^8); quy uoc inv(0) = 0 (dung theo AES)."""
    if a == 0:
        return 0
    for y in range(1, 256):
        if gmul(a, y) == 1:
            return y


def rotl8(x, k):
    return ((x << k) | (x >> (8 - k))) & 0xFF


def make_sbox():
    """S-box = bien doi affine cua nghich dao nhan:
       s = inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63"""
    sbox = []
    for x in range(256):
        i = ginv(x)
        sbox.append(i ^ rotl8(i, 1) ^ rotl8(i, 2) ^ rotl8(i, 3) ^ rotl8(i, 4) ^ 0x63)
    return sbox


SBOX = make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ----------------------------------------------------------------------------
# 2. KEY EXPANSION: khoa 16 byte -> 11 khoa vong (moi khoa 16 byte)
# ----------------------------------------------------------------------------
def key_expansion(key, log=None):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]       # w[0..3] = khoa goc
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                                # RotWord
            t = [SBOX[x] for x in t]                         # SubWord
            t[0] ^= RCON[i // 4 - 1]                         # xor Rcon
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])     # w[i] = w[i-4] xor t
    round_keys = [sum(w[4 * r:4 * r + 4], []) for r in range(11)]
    if log:
        for i in range(44):
            log("w[{:2d}] = {}".format(i, bytes(w[i]).hex()))
        for r in range(11):
            log("round key {:2d} = {}".format(r, bytes(round_keys[r]).hex()))
    return round_keys


# ----------------------------------------------------------------------------
# 3. CAC PHEP BIEN DOI TREN STATE (list 16 byte, chi so i = r + 4c)
# ----------------------------------------------------------------------------
def add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]


def sub_bytes(s):
    return [SBOX[x] for x in s]


def inv_sub_bytes(s):
    return [INV_SBOX[x] for x in s]


def shift_rows(s):
    """Hang r dich vong trai r vi tri: new[r][c] = old[r][(c+r) % 4]."""
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    """Hang r dich vong phai r vi tri: new[r][c] = old[r][(c-r) % 4]."""
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(s):
    """Nhan tung cot voi ma tran [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] trong GF(2^8)."""
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3,
                a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3,
                a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3),
                gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)]
    return out


def inv_mix_columns(s):
    """Ma tran nghich dao: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]."""
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
                gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
                gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
                gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)]
    return out


def hx(s):
    return bytes(s).hex()


def matrix(s):
    """In state dang ma tran 4x4 (hang r, cot c)."""
    return "\n".join("        " + " ".join("{:02x}".format(s[r + 4 * c]) for c in range(4))
                     for r in range(4))


# ----------------------------------------------------------------------------
# 4. MA HOA / GIAI MA MOT KHOI 16 BYTE
# ----------------------------------------------------------------------------
def encrypt_block(pt, key, log=None):
    rks = key_expansion(key, log)
    s = list(pt)
    if log:
        log("")
        log("round[ 0].input    {}".format(hx(s)))
        log("round[ 0].k_sch    {}".format(hx(rks[0])))
    s = add_round_key(s, rks[0])                  # vong 0: chi AddRoundKey
    for r in range(1, 11):
        if log:
            log("round[{:2d}].start    {}".format(r, hx(s)))
            log(matrix(s))
        s = sub_bytes(s)
        if log:
            log("round[{:2d}].s_box    {}".format(r, hx(s)))
        s = shift_rows(s)
        if log:
            log("round[{:2d}].s_row    {}".format(r, hx(s)))
        if r != 10:                               # vong cuoi KHONG co MixColumns
            s = mix_columns(s)
            if log:
                log("round[{:2d}].m_col    {}".format(r, hx(s)))
        if log:
            log("round[{:2d}].k_sch    {}".format(r, hx(rks[r])))
        s = add_round_key(s, rks[r])
        if log:
            log("round[{:2d}].output   {}".format(r, hx(s)))
            log(matrix(s))
    return bytes(s)


def decrypt_block(ct, key, log=None):
    rks = key_expansion(key)
    s = add_round_key(list(ct), rks[10])
    if log:
        log("round[10].iinput   {}".format(hx(ct)))
    for r in range(9, -1, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, rks[r])
        if r != 0:
            s = inv_mix_columns(s)
        if log:
            log("round[{:2d}].ioutput  {}".format(r, hx(s)))
    return bytes(s)


def parse_hex(text, nbytes=16):
    """Hex -> bytes. Neu ngan hon nbytes thi them 0 vao BEN TRAI (hieu nhu mot so nguyen)."""
    text = text.lower().removeprefix("0x")
    return bytes.fromhex(text.rjust(2 * nbytes, "0"))


def main():
    ap = argparse.ArgumentParser(description="AES-128 tu cai dat, co in cac buoc trung gian")
    ap.add_argument("--key", required=True, help="khoa hex (toi da 32 ky tu)")
    ap.add_argument("--pt", help="ban ro hex, khi ma hoa")
    ap.add_argument("--ct", help="ban ma hex, khi giai ma")
    ap.add_argument("--decrypt", action="store_true")
    a = ap.parse_args()
    key = parse_hex(a.key)
    if a.decrypt:
        out = decrypt_block(parse_hex(a.ct), key, log=print)
    else:
        out = encrypt_block(parse_hex(a.pt), key, log=print)
    print("\nKet qua = " + out.hex())


if __name__ == "__main__":
    main()
