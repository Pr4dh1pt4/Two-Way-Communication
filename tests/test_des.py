"""Pengujian DES (test vector standar) dan mode CBC + PKCS#7."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from des import DES, decrypt_block, encrypt_block, generate_subkeys  # noqa: E402
from modes import (  # noqa: E402
    DecryptionError,
    PaddingError,
    cbc_decrypt,
    cbc_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
)

KEY = bytes.fromhex("133457799BBCDFF1")
WRONG_KEY = bytes.fromhex("0E329232EA6D0D73")


class TestDESVectors(unittest.TestCase):
    # (key, plaintext, ciphertext) - test vector DES standar yang di-hardcode.
    VECTORS = [
        # Contoh klasik (J. Orlin Grabbe, "The DES Algorithm Illustrated")
        ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
        # Contoh klasik lain: plaintext 8787... menjadi nol semua
        ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
        # Key nol, plaintext nol
        ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
    ]

    def test_encrypt_vectors(self):
        for k, p, c in self.VECTORS:
            with self.subTest(key=k):
                subkeys = generate_subkeys(bytes.fromhex(k))
                self.assertEqual(encrypt_block(bytes.fromhex(p), subkeys).hex().upper(), c)

    def test_decrypt_vectors(self):
        for k, p, c in self.VECTORS:
            with self.subTest(key=k):
                subkeys = generate_subkeys(bytes.fromhex(k))
                self.assertEqual(decrypt_block(bytes.fromhex(c), subkeys).hex().upper(), p)

    def test_class_wrapper(self):
        d = DES(KEY)
        c = d.encrypt_block(bytes.fromhex("0123456789ABCDEF"))
        self.assertEqual(c.hex().upper(), "85E813540F0AB405")
        self.assertEqual(d.decrypt_block(c).hex().upper(), "0123456789ABCDEF")

    def test_subkey_count_and_size(self):
        subkeys = generate_subkeys(KEY)
        self.assertEqual(len(subkeys), 16)
        for k in subkeys:
            self.assertLess(k, 1 << 48)
        # K1 dari contoh Grabbe: 000110 110000 001011 101111 111111 000111 000001 110010
        self.assertEqual(subkeys[0], 0b000110110000001011101111111111000111000001110010)

    def test_invalid_key_length(self):
        for bad in (b"", b"1234567", b"123456789"):
            with self.assertRaises(ValueError):
                generate_subkeys(bad)

    def test_repr_hides_key(self):
        self.assertNotIn("1334", repr(DES(KEY)))


class TestPKCS7(unittest.TestCase):
    def test_pad_lengths(self):
        self.assertEqual(pkcs7_pad(b""), b"\x08" * 8)
        self.assertEqual(pkcs7_pad(b"A"), b"A" + b"\x07" * 7)
        self.assertEqual(pkcs7_pad(b"12345678"), b"12345678" + b"\x08" * 8)

    def test_unpad_roundtrip(self):
        for n in range(0, 20):
            data = os.urandom(n)
            self.assertEqual(pkcs7_unpad(pkcs7_pad(data)), data)

    def test_unpad_invalid(self):
        bad_inputs = [
            b"",                         # kosong
            b"1234567",                  # bukan kelipatan 8
            b"1234567\x00",              # nilai padding 0
            b"1234567\x09",              # nilai padding > 8
            b"123456\x01\x02",           # byte padding tidak konsisten
            b"12345\x03\x02\x03",
        ]
        for data in bad_inputs:
            with self.subTest(data=data):
                with self.assertRaises(PaddingError):
                    pkcs7_unpad(data)


class TestCBC(unittest.TestCase):
    MESSAGES = [
        b"",
        b"A",
        b"12345678",                       # tepat 8 byte
        b"0123456789ABCDEF",               # 16 byte
        b"Pesan panjang " * 50,            # panjang
        "Halo, apa kabar? Saya sedang belajar keamanan informasi 🔐😀 — ñ é".encode("utf-8"),
        "Selamat pagi, Bapak/Ibu dosen! Ini kuliah Kriptografi 🇮🇩".encode("utf-8"),
    ]

    def test_roundtrip(self):
        for msg in self.MESSAGES:
            with self.subTest(length=len(msg)):
                iv, ct = cbc_encrypt(KEY, msg)
                self.assertEqual(len(iv), 8)
                self.assertEqual(len(ct) % 8, 0)
                self.assertGreater(len(ct), len(msg))
                self.assertEqual(cbc_decrypt(KEY, iv, ct), msg)

    def test_utf8_text_roundtrip(self):
        text = "Kriptografi itu seru 🎉 — huruf: àéîõü, ẞ, 日本語"
        iv, ct = cbc_encrypt(KEY, text.encode("utf-8"))
        self.assertEqual(cbc_decrypt(KEY, iv, ct).decode("utf-8"), text)

    def test_same_message_different_ciphertext(self):
        msg = b"Pesan yang sama persis"
        iv1, ct1 = cbc_encrypt(KEY, msg)
        iv2, ct2 = cbc_encrypt(KEY, msg)
        self.assertNotEqual(iv1, iv2)
        self.assertNotEqual(ct1, ct2)
        self.assertEqual(cbc_decrypt(KEY, iv1, ct1), cbc_decrypt(KEY, iv2, ct2))

    def test_fixed_iv_is_deterministic(self):
        iv = bytes(8)
        self.assertEqual(cbc_encrypt(KEY, b"abc", iv), cbc_encrypt(KEY, b"abc", iv))

    def test_cbc_first_block_matches_ecb_with_zero_iv(self):
        # Dengan IV nol, blok pertama CBC = DES(P0) -> cocok dengan test vector.
        _, ct = cbc_encrypt(KEY, bytes.fromhex("0123456789ABCDEF"), bytes(8))
        self.assertEqual(ct[:8].hex().upper(), "85E813540F0AB405")

    def test_wrong_key_fails_gracefully(self):
        # IV tetap supaya hasil deterministik.
        iv, ct = cbc_encrypt(KEY, b"Rahasia negara: jangan dibaca!", bytes(8))
        with self.assertRaises(DecryptionError):
            cbc_decrypt(WRONG_KEY, iv, ct)

    def test_wrong_key_never_crashes(self):
        # Dengan key salah, hasilnya harus DecryptionError atau data sampah,
        # tidak boleh exception lain (crash) dan tidak boleh mengembalikan plaintext asli.
        msg = b"Pesan uji key salah"
        for _ in range(200):
            iv, ct = cbc_encrypt(KEY, msg)
            try:
                result = cbc_decrypt(os.urandom(8), iv, ct)
            except DecryptionError:
                continue
            self.assertNotEqual(result, msg)

    def test_corrupted_ciphertext(self):
        iv, ct = cbc_encrypt(KEY, b"data penting", bytes(8))
        corrupted = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with self.assertRaises(DecryptionError):
            cbc_decrypt(KEY, iv, corrupted)

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(DecryptionError):
            cbc_decrypt(KEY, bytes(8), b"")
        with self.assertRaises(DecryptionError):
            cbc_decrypt(KEY, bytes(8), b"1234567")
        with self.assertRaises(DecryptionError):
            cbc_decrypt(KEY, b"short", bytes(8))


if __name__ == "__main__":
    unittest.main()
