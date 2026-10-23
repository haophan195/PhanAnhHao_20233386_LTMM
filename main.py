"""Chương trình dòng lệnh: nhân hai phần tử trong GF(2^4) hoặc GF(2^8)."""
import argparse

from gf import (IRREDUCIBLE_GF16, IRREDUCIBLE_GF256, gf_mul, poly_to_str)

FIELDS = {
    4: IRREDUCIBLE_GF16,
    8: IRREDUCIBLE_GF256,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Nhân hai đa thức trong trường hữu hạn GF(2^m)")
    parser.add_argument("-m", type=int, choices=sorted(FIELDS), required=True,
                        help="chọn trường GF(2^m): 4 hoặc 8")
    parser.add_argument("a", help="đa thức thứ nhất (hex 0x.. hoặc bin 0b..)")
    parser.add_argument("b", help="đa thức thứ hai (hex 0x.. hoặc bin 0b..)")
    args = parser.parse_args()

    a, b = int(args.a, 0), int(args.b, 0)
    mod = FIELDS[args.m]
    c = gf_mul(a, b, mod)

    print(f"Trường GF(2^{args.m}), đa thức tối giản: {poly_to_str(mod)}")
    print(f"a = {poly_to_str(a)}  ({a:#0{args.m // 4 + 2}x})")
    print(f"b = {poly_to_str(b)}  ({b:#0{args.m // 4 + 2}x})")
    print(f"a * b = {poly_to_str(c)}  ({c:#0{args.m // 4 + 2}x})")


if __name__ == "__main__":
    main()
