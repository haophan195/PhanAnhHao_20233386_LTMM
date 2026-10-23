# Nhân đa thức trong trường hữu hạn GF(2^4) và GF(2^8)

Bài tập: cài đặt giải thuật nhân hai đa thức trong GF(2^4), GF(2^8) tương ứng với đa thức tối giản của trường.

## Cơ sở toán học

- GF(2^m) gồm các đa thức bậc ≤ m−1 với hệ số trong GF(2) = {0, 1}.
- Phép cộng: cộng hệ số theo mod 2, tức là **XOR** các bit.
- Phép nhân: nhân đa thức rồi lấy dư khi chia cho một **đa thức tối giản** bậc m.

| Trường   | Đa thức tối giản          | Dạng nhị phân |
|----------|---------------------------|---------------|
| GF(2^4)  | x^4 + x + 1               | 0b10011       |
| GF(2^8)  | x^8 + x^4 + x^3 + x + 1   | 0x11B (AES)   |

Mỗi đa thức được lưu bằng một số nguyên, bit i là hệ số của x^i.

## Thuật toán

`gf_mul` dùng **shift-and-add**: duyệt từng bit của b, nếu bit bằng 1 thì XOR a vào kết quả,
sau đó a ← a·x (dịch trái 1 bit) và rút gọn bằng XOR với đa thức tối giản khi bậc đạt m.
Độ phức tạp O(m). `gf_mul_poly_then_mod` là cách nhân rồi chia lấy dư, dùng để đối chiếu.

## Chạy thử

```bash
python main.py -m 8 0x57 0x83      # GF(2^8): 0x57 * 0x83 = 0xc1
python main.py -m 4 0b1011 0b0101  # GF(2^4): kết quả 0x1
python -m unittest -v              # chạy kiểm thử
```

## Kiểm thử

- Ví dụ chuẩn trong FIPS-197 (AES): {57}·{83} = {C1}.
- Kiểm tra toàn bộ cặp phần tử: giao hoán, phần tử đơn vị/không, hai thuật toán cho kết quả trùng.
- Mọi phần tử khác 0 đều có nghịch đảo (xác nhận đây là một trường).

## Người thực hiện

Phan Anh Hao - 20233386
