"""
DES (Data Encryption Standard) - cai dat tu dau, in gia tri trung gian tung vong.

Cach dung:
    python des.py --key 133457799BBCDFF1 --pt 0123456789ABCDEF
    python des.py --key 133457799BBCDFF1 --ct 85E813540F0AB405 --decrypt

Quy uoc: moi khoi 64 bit, khoa 64 bit (gom 8 bit parity), viet dang hex.
Cac bang hoan vi dung chi so bat dau tu 1 va dem tu bit trai nhat (MSB) nhu trong
tai lieu chuan FIPS 46-3.
"""
import argparse

# ----------------------------------------------------------------------------
# 1. CAC BANG CO DINH CUA DES
# ----------------------------------------------------------------------------
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# Mo rong 32 bit -> 48 bit
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Hoan vi P sau khoi S-box (32 bit)
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# Lich khoa: PC-1 (64 -> 56 bit, bo 8 bit parity), PC-2 (56 -> 48 bit)
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# So bit dich trai vong cua C va D o moi vong
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 S-box, moi S-box 4 hang x 16 cot (khop Table 3.3 trong de bai tuan 10)
SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


# ----------------------------------------------------------------------------
# 2. HAM TIEN ICH
# ----------------------------------------------------------------------------
def permute(x, table, n_in):
    """Hoan vi / chon bit: bit thu i cua ket qua = bit thu table[i] cua x.
    x la so nguyen n_in bit; bit 1 la bit trai nhat (MSB)."""
    out = 0
    for pos in table:
        out = (out << 1) | ((x >> (n_in - pos)) & 1)
    return out


def rotl(x, k, n):
    """Dich vong trai k bit tren so n bit."""
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1)


def b(x, n):
    """Chuoi nhi phan n bit."""
    return format(x, "0{}b".format(n))


def groups(x, n, size):
    """Chuoi nhi phan chia nhom 'size' bit cho de doc."""
    s = b(x, n)
    return " ".join(s[i:i + size] for i in range(0, n, size))


# ----------------------------------------------------------------------------
# 3. LICH KHOA (KEY SCHEDULE)
# ----------------------------------------------------------------------------
def key_schedule(key64, log=None):
    """Sinh 16 khoa con 48 bit tu khoa 64 bit."""
    k56 = permute(key64, PC1, 64)                 # PC-1: bo 8 bit parity, hoan vi
    c, d = k56 >> 28, k56 & 0xFFFFFFF             # tach C0, D0 (moi nua 28 bit)
    if log:
        log("K+ (sau PC-1, 56 bit) = " + groups(k56, 56, 7))
        log("C0 = " + groups(c, 28, 7))
        log("D0 = " + groups(d, 28, 7))
    subkeys = []
    for i in range(16):
        c, d = rotl(c, SHIFTS[i], 28), rotl(d, SHIFTS[i], 28)
        k48 = permute((c << 28) | d, PC2, 56)     # PC-2: chon 48 trong 56 bit
        subkeys.append(k48)
        if log:
            log("C{0:<2d} = {1}   D{0:<2d} = {2}   (dich {3} bit)".format(
                i + 1, groups(c, 28, 7), groups(d, 28, 7), SHIFTS[i]))
            log("K{:<2d} = {} = 0x{:012X}".format(i + 1, groups(k48, 48, 6), k48))
    return subkeys


# ----------------------------------------------------------------------------
# 4. HAM VONG f(R, K)
# ----------------------------------------------------------------------------
def feistel(r32, k48, log=None):
    """f(R, K) = P( S( E(R) xor K ) )"""
    er = permute(r32, E, 32)                      # mo rong R: 32 -> 48 bit
    x = er ^ k48                                  # xor voi khoa con
    s_out = 0
    for i in range(8):                            # 8 nhom 6 bit -> 8 nhom 4 bit
        six = (x >> (42 - 6 * i)) & 0x3F
        row = ((six >> 4) & 0b10) | (six & 1)     # hang = bit 1 va bit 6
        col = (six >> 1) & 0xF                    # cot  = bit 2..5
        s_out = (s_out << 4) | SBOX[i][row][col]
    f = permute(s_out, P, 32)                     # hoan vi P
    if log:
        log("    E(R)        = " + groups(er, 48, 6))
        log("    E(R) xor K  = " + groups(x, 48, 6))
        log("    S-box out   = " + groups(s_out, 32, 4) + "  (0x{:08X})".format(s_out))
        log("    P(S-box)=f  = " + groups(f, 32, 4) + "  (0x{:08X})".format(f))
    return f


# ----------------------------------------------------------------------------
# 5. MA HOA / GIAI MA MOT KHOI
# ----------------------------------------------------------------------------
def des_block(block64, key64, decrypt=False, log=None):
    subkeys = key_schedule(key64, log)
    if decrypt:                                   # giai ma = dung khoa con theo thu tu nguoc
        subkeys = subkeys[::-1]

    ip = permute(block64, IP, 64)
    l, r = ip >> 32, ip & 0xFFFFFFFF
    if log:
        log("")
        log("Khoi vao      = 0x{:016X}".format(block64))
        log("Sau IP        = " + groups(ip, 64, 8) + "  (0x{:016X})".format(ip))
        log("L0 = 0x{:08X}   R0 = 0x{:08X}".format(l, r))

    for i in range(16):
        if log:
            log("--- Vong {} (dung K{}) ---".format(i + 1, 16 - i if decrypt else i + 1))
        f = feistel(r, subkeys[i], log)
        l, r = r, l ^ f                           # L_i = R_{i-1};  R_i = L_{i-1} xor f
        if log:
            log("    L{0} = 0x{1:08X}   R{0} = 0x{2:08X}".format(i + 1, l, r))

    pre = (r << 32) | l                           # dao vi tri: R16 L16
    out = permute(pre, FP, 64)                    # hoan vi cuoi IP^-1
    if log:
        log("")
        log("R16 L16 (truoc IP^-1) = 0x{:016X}".format(pre))
        log("Khoi ra (sau IP^-1)   = 0x{:016X}".format(out))
    return out


def main():
    ap = argparse.ArgumentParser(description="DES tu cai dat, co in cac buoc trung gian")
    ap.add_argument("--key", required=True, help="khoa 64 bit, 16 ky tu hex")
    ap.add_argument("--pt", help="ban ro 64 bit (hex), khi ma hoa")
    ap.add_argument("--ct", help="ban ma 64 bit (hex), khi giai ma")
    ap.add_argument("--decrypt", action="store_true")
    a = ap.parse_args()
    data = int(a.ct if a.decrypt else a.pt, 16)
    des_block(data, int(a.key, 16), decrypt=a.decrypt, log=print)


if __name__ == "__main__":
    main()
