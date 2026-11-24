# DES và AES-128 (môn Lý thuyết mật mã)

Cài đặt DES và AES-128 bằng Python 3 (không dùng thư viện mật mã), in giá trị trung gian
của từng vòng để đối chiếu test vector.

## Cấu trúc
- `des.py` – DES: lịch khoá (PC-1, dịch vòng, PC-2), IP, 16 vòng Feistel (E, XOR khoá, 8 S-box, P), IP⁻¹.
- `aes.py` – AES-128: S-box sinh từ nghịch đảo trong GF(2^8) + biến đổi affine, KeyExpansion,
  SubBytes, ShiftRows, MixColumns, AddRoundKey; có cả giải mã.
- `test_vectors.py` – kiểm tra với test vector chuẩn và ghi vết chạy vào `output/`.
- `output/` – kết quả chạy: giá trị từng trạng thái của DES và AES, và đối chiếu bảng IP/E/P của bài tuần 10 (`tuan10_tables.txt`).

## Chạy
```
python test_vectors.py
python des.py --key 133457799BBCDFF1 --pt 0123456789ABCDEF
python aes.py --key 000102030405060708090a0b0c0d0e0f --pt 00112233445566778899aabbccddeeff
```
Với AES, giá trị hex ngắn hơn 128 bit được thêm số 0 vào bên trái (hiểu như một số nguyên).
