"""Kiểm thử bằng unittest:  python -m unittest -v"""
import unittest

from gf import (IRREDUCIBLE_GF16, IRREDUCIBLE_GF256, gf16_mul, gf256_mul,
                gf_mul, gf_mul_poly_then_mod)


def inverse(a, modulus):
    """Tìm nghịch đảo bằng cách thử hết (chỉ dùng để kiểm thử)."""
    return next(b for b in range(1, 1 << (modulus.bit_length() - 1))
                if gf_mul(a, b, modulus) == 1)


class TestKnownValues(unittest.TestCase):
    def test_aes_fips197_example(self):
        # FIPS-197, mục 4.2: {57} • {83} = {c1}
        self.assertEqual(gf256_mul(0x57, 0x83), 0xC1)

    def test_aes_fips197_xtime_chain(self):
        # {57} • {02} = {ae}, {57} • {04} = {47}, {57} • {13} = {fe}
        self.assertEqual(gf256_mul(0x57, 0x02), 0xAE)
        self.assertEqual(gf256_mul(0x57, 0x04), 0x47)
        self.assertEqual(gf256_mul(0x57, 0x13), 0xFE)

    def test_gf16_by_hand(self):
        # (x^3 + x + 1)(x^2 + 1) = x^5 + x^3 + x^3 + x^2 + x + 1
        #                        = x^5 + x^2 + x + 1
        # x^5 mod (x^4+x+1) = x^2 + x  =>  kết quả = 1  (hai phần tử nghịch đảo nhau)
        self.assertEqual(gf16_mul(0b1011, 0b0101), 0b0001)


class TestFieldAxioms(unittest.TestCase):
    def check_field(self, modulus):
        size = 1 << (modulus.bit_length() - 1)
        for a in range(size):
            self.assertEqual(gf_mul(a, 1, modulus), a)   # phần tử đơn vị
            self.assertEqual(gf_mul(a, 0, modulus), 0)   # phần tử không
            for b in range(size):
                # giao hoán
                self.assertEqual(gf_mul(a, b, modulus), gf_mul(b, a, modulus))
                # hai thuật toán cho cùng kết quả
                self.assertEqual(gf_mul(a, b, modulus),
                                 gf_mul_poly_then_mod(a, b, modulus))
        # mọi phần tử khác 0 đều có nghịch đảo -> đây là một trường
        for a in range(1, size):
            self.assertEqual(gf_mul(a, inverse(a, modulus), modulus), 1)

    def test_gf16(self):
        self.check_field(IRREDUCIBLE_GF16)

    def test_gf256(self):
        self.check_field(IRREDUCIBLE_GF256)

    def test_associativity_gf16(self):
        for a in range(16):
            for b in range(16):
                for c in range(16):
                    self.assertEqual(gf16_mul(gf16_mul(a, b), c),
                                     gf16_mul(a, gf16_mul(b, c)))

    def test_distributive_gf256_sampled(self):
        for a in range(0, 256, 7):
            for b in range(256):
                for c in range(0, 256, 11):
                    self.assertEqual(gf256_mul(a, b ^ c),
                                     gf256_mul(a, b) ^ gf256_mul(a, c))

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            gf16_mul(16, 1)


if __name__ == "__main__":
    unittest.main()
