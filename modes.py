"""
modes.py - Padding PKCS#7 dan mode operasi CBC untuk DES, implementasi manual.

CBC (Cipher Block Chaining):
    Enkripsi:  C_0 = E_K(P_0 XOR IV)
               C_i = E_K(P_i XOR C_{i-1})
    Dekripsi:  P_0 = D_K(C_0) XOR IV
               P_i = D_K(C_i) XOR C_{i-1}

IV acak 8 byte dibangkitkan per pesan (os.urandom) sehingga pesan yang sama
menghasilkan ciphertext berbeda. IV bukan rahasia dan dikirim terbuka.
"""

import os

from des import BLOCK_SIZE, DES


class PaddingError(ValueError):
    """Padding tidak valid -> biasanya key salah atau ciphertext rusak."""


class DecryptionError(ValueError):
    """Kegagalan dekripsi umum (key salah / data rusak / format tidak valid)."""


# ---------------------------------------------------------------------------
# PKCS#7
# ---------------------------------------------------------------------------

def pkcs7_pad(data, block_size=BLOCK_SIZE):
    """
    Tambahkan N byte bernilai N (1 <= N <= block_size).
    Jika data sudah kelipatan block_size, tetap ditambah satu blok penuh,
    sehingga unpad selalu tidak ambigu.
    """
    n = block_size - (len(data) % block_size)
    return bytes(data) + bytes([n]) * n


def pkcs7_unpad(data, block_size=BLOCK_SIZE):
    """Buang padding PKCS#7 dengan validasi ketat."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise PaddingError("Panjang data tidak valid untuk unpad")
    n = data[-1]
    if n < 1 or n > block_size:
        raise PaddingError("Nilai padding di luar jangkauan")
    if data[-n:] != bytes([n]) * n:
        raise PaddingError("Byte padding tidak konsisten")
    return data[:-n]


# ---------------------------------------------------------------------------
# CBC
# ---------------------------------------------------------------------------

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def generate_iv():
    """IV acak 8 byte. os.urandom hanya dipakai untuk keacakan IV."""
    return os.urandom(BLOCK_SIZE)


def cbc_encrypt(key, plaintext, iv=None):
    """
    Enkripsi bytes dengan panjang bebas memakai DES-CBC + PKCS#7.
    Mengembalikan tuple (iv, ciphertext).
    """
    if iv is None:
        iv = generate_iv()
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV harus tepat 8 byte")

    cipher = DES(key)
    data = pkcs7_pad(plaintext)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = cipher.encrypt_block(_xor(data[i:i + BLOCK_SIZE], prev))
        out += block
        prev = block
    return iv, bytes(out)


def cbc_decrypt(key, iv, ciphertext):
    """
    Dekripsi DES-CBC lalu unpad. Melempar DecryptionError jika gagal
    (key salah, ciphertext rusak, atau panjang tidak valid).
    """
    if len(iv) != BLOCK_SIZE:
        raise DecryptionError("IV harus tepat 8 byte")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise DecryptionError("Panjang ciphertext bukan kelipatan 8 byte")

    cipher = DES(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        out += _xor(cipher.decrypt_block(block), prev)
        prev = block

    try:
        return pkcs7_unpad(bytes(out))
    except PaddingError as exc:
        raise DecryptionError("Padding tidak valid") from exc
