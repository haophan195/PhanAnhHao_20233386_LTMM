"""
Nhân hai phần tử trong trường hữu hạn GF(2^m) (Galois field).

Một phần tử của GF(2^m) là đa thức bậc <= m-1 với hệ số trong GF(2) = {0, 1}.
Ta biểu diễn đa thức bằng một số nguyên: bit thứ i là hệ số của x^i.
    Ví dụ: x^3 + x + 1  ->  0b1011  ->  0x0B

Phép cộng trong GF(2^m) là XOR (vì 1 + 1 = 0 trong GF(2)).
Phép nhân = nhân đa thức rồi lấy dư theo đa thức tối giản (irreducible polynomial).
"""

# Đa thức tối giản, biểu diễn đầy đủ (gồm cả số hạng bậc m).
IRREDUCIBLE_GF16 = 0b10011        # x^4 + x + 1
IRREDUCIBLE_GF256 = 0b100011011   # x^8 + x^4 + x^3 + x + 1  (đa thức của AES)


def poly_to_str(a: int) -> str:
    """Chuyển số nguyên thành chuỗi đa thức, ví dụ 0b1011 -> 'x^3 + x + 1'."""
    if a == 0:
        return "0"
    terms = []
    for i in range(a.bit_length() - 1, -1, -1):
        if (a >> i) & 1:
            terms.append("1" if i == 0 else "x" if i == 1 else f"x^{i}")
    return " + ".join(terms)


def gf_mul(a: int, b: int, modulus: int) -> int:
    """
    Nhân a và b trong GF(2^m) với đa thức tối giản `modulus` (bậc m).

    Thuật toán shift-and-add (còn gọi là "Russian peasant"):
      - Duyệt từng bit của b từ thấp đến cao.
      - Nếu bit đó bằng 1 thì cộng (XOR) a hiện tại vào kết quả.
      - Sau mỗi bước, nhân a với x (dịch trái 1 bit). Nếu bậc của a đạt m
        thì rút gọn bằng cách XOR với modulus (tương đương a mod modulus).
    Độ phức tạp: O(m) phép dịch bit/XOR.
    """
    m = modulus.bit_length() - 1          # bậc của đa thức tối giản
    if not (0 <= a < (1 << m) and 0 <= b < (1 << m)):
        raise ValueError(f"Toán hạng phải là đa thức bậc <= {m - 1}")

    result = 0
    for _ in range(m):
        if b & 1:                # hệ số hiện tại của b là 1 -> cộng a vào kết quả
            result ^= a
        b >>= 1
        a <<= 1                  # a <- a * x
        if (a >> m) & 1:         # bậc đạt m -> rút gọn theo modulus
            a ^= modulus
    return result


def gf_mul_poly_then_mod(a: int, b: int, modulus: int) -> int:
    """
    Cách thứ hai (để đối chiếu): nhân đa thức không rút gọn, rồi chia lấy dư.
    Bước 1: tích đa thức thông thường (carry-less multiplication) có bậc <= 2m-2.
    Bước 2: chia dài đa thức cho modulus trên GF(2), lấy phần dư.
    """
    m = modulus.bit_length() - 1
    product = 0
    for i in range(b.bit_length()):
        if (b >> i) & 1:
            product ^= a << i
    for shift in range(product.bit_length() - 1, m - 1, -1):
        if (product >> shift) & 1:
            product ^= modulus << (shift - m)
    return product


def gf16_mul(a: int, b: int) -> int:
    """Nhân trong GF(2^4) với x^4 + x + 1."""
    return gf_mul(a, b, IRREDUCIBLE_GF16)


def gf256_mul(a: int, b: int) -> int:
    """Nhân trong GF(2^8) với x^8 + x^4 + x^3 + x + 1."""
    return gf_mul(a, b, IRREDUCIBLE_GF256)
