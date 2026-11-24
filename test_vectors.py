"""
Kiem thu DES va AES-128 bang cac test vector chuan, dong thoi ghi lai vet chay
(gia tri tung vong) vao thu muc output/ de nop len git.

Chay:  python test_vectors.py
"""
import os

import aes
import des

# (khoa, ban ro, ban ma mong doi) - cac gia tri cong bo trong tai lieu
DES_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),  # vi du tu tai lieu DES pho bien
    ("0101010101010101", "0000000000000000", "8CA64DE9C1B123A7"),  # khoa yeu, khoa/ban ro toan 0
    ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),  # "Now is t"
]

AES_VECTORS = [
    # FIPS-197 Appendix C.1
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
    # FIPS-197 Appendix B
    ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
     "3925841d02dc09fbdc118597196a0b32"),
]


def check_des():
    for key, pt, ct in DES_VECTORS:
        k, p, c = int(key, 16), int(pt, 16), int(ct, 16)
        assert des.des_block(p, k) == c, "DES ma hoa sai voi khoa " + key
        assert des.des_block(c, k, decrypt=True) == p, "DES giai ma sai voi khoa " + key
        print("DES OK  key={} pt={} -> ct={}".format(key, pt, ct))


def check_aes():
    for key, pt, ct in AES_VECTORS:
        k, p, c = bytes.fromhex(key), bytes.fromhex(pt), bytes.fromhex(ct)
        assert aes.encrypt_block(p, k) == c, "AES ma hoa sai voi khoa " + key
        assert aes.decrypt_block(c, k) == p, "AES giai ma sai voi khoa " + key
        print("AES OK  key={} pt={} -> ct={}".format(key, pt, ct))
    # S-box phai dung cac gia tri da biet
    assert aes.SBOX[0x00] == 0x63 and aes.SBOX[0x53] == 0xED and aes.SBOX[0xFF] == 0x16
    print("AES S-box OK")


# ---------------------------------------------------------------------------
# Bai tap tuan 10: cac bang IP, E, P cua sinh vien (danh so bit tu 0, b0..b63)
# ---------------------------------------------------------------------------
# IP: 32 phan tu dau la nua tren, 32 phan tu sau la nua duoi
TUAN10_IP = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
             61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
             56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
             60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]
# E: ghi theo nhan bit goc, ap dung len NUA TREN cua ket qua IP (nhan "Right" trong vo)
TUAN10_E = [7, 57, 49, 41, 33, 25, 33, 25, 17, 9, 1, 59,
            1, 59, 51, 43, 35, 27, 35, 27, 19, 11, 3, 61,
            3, 61, 53, 45, 37, 29, 37, 29, 21, 13, 5, 63,
            5, 63, 55, 47, 39, 31, 39, 31, 23, 15, 7, 57]
# P: ghi theo vi tri trong vector 32 bit
TUAN10_P = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
            1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]


def fmt_rows(values, per_row):
    return ["   " + " ".join("b{:<3d}".format(v) for v in values[i:i + per_row])
            for i in range(0, len(values), per_row)]


def check_tuan10():
    """Sinh lai IP, E, P tu des.py (doi sang chi so tu 0) va so voi bang trong vo."""
    ip = [x - 1 for x in des.IP]
    top, bottom = ip[:32], ip[32:]
    e_top = [top[x - 1] for x in des.E]          # E ap len nua tren (quy uoc trong vo)
    e_std = [bottom[x - 1] for x in des.E]       # E ap len nua duoi = R0 theo chuan DES
    p = [x - 1 for x in des.P]

    ok_ip, ok_e, ok_p = ip == TUAN10_IP, e_top == TUAN10_E, p == TUAN10_P
    assert ok_ip and ok_e and ok_p, "Bang tuan 10 khong khop des.py"
    print("Bang tuan 10 (IP, E, P) KHOP voi des.py")

    lines = ["Bai tap tuan 10 - doi chieu bang IP, E, P voi des.py (bit danh so tu 0)",
             "=" * 70, "",
             "IP  - khop: {}  (8 hang dau = nua tren, 8 hang sau = nua duoi)".format(ok_ip)]
    lines += fmt_rows(ip, 8)
    lines += ["", "E (ap len nua tren cua IP, theo vo) - khop: {}".format(ok_e)]
    lines += fmt_rows(e_top, 6)
    lines += ["", "P - khop: {}".format(ok_p)]
    lines += fmt_rows(p, 8)
    lines += ["", "Tham khao: E ap len nua DUOI cua IP (R0 theo chuan FIPS 46-3), khong so sanh voi vo"]
    lines += fmt_rows(e_std, 6)
    os.makedirs("output", exist_ok=True)
    with open("output/tuan10_tables.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("Da ghi output/tuan10_tables.txt")


def write_trace(path, title, runner):
    lines = [title, "=" * len(title)]
    runner(lines.append)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("Da ghi " + path)


def main():
    check_des()
    check_aes()
    check_tuan10()

    os.makedirs("output", exist_ok=True)

    # DES: vet chay day du cho vi du chuan (khoa 133457799BBCDFF1)
    write_trace("output/des_trace.txt",
                "DES  key=133457799BBCDFF1  plaintext=0123456789ABCDEF",
                lambda log: des.des_block(0x0123456789ABCDEF, 0x133457799BBCDFF1, log=log))

    # AES: vi du FIPS-197 Appendix C.1 (de doi chieu voi tai lieu)
    write_trace("output/aes_trace_fips197.txt",
                "AES-128  key=000102..0f  plaintext=00112233..ff (FIPS-197 C.1)",
                lambda log: aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"),
                                              bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                                              log=log))

    # AES: bai tap tuan 11 (p = 0x0000000000000011, k = 0x0000000000000000)
    # Input 64 bit duoc them 0 vao ben trai thanh 128 bit (xem README)
    write_trace("output/aes_trace_tuan11.txt",
                "AES-128  key=0x0000000000000000  plaintext=0x0000000000000011 (bai tap tuan 11)",
                lambda log: aes.encrypt_block(aes.parse_hex("0000000000000011"),
                                              aes.parse_hex("0000000000000000"),
                                              log=log))
    print("\nTat ca test deu dat.")


if __name__ == "__main__":
    main()
