"""
protocol.py - Framing pesan di atas TCP.

Format satu frame:
    +----------------------+------------------------------+
    | panjang (4 byte, BE) | payload JSON (UTF-8)         |
    +----------------------+------------------------------+

TCP adalah stream, bukan pesan: satu send() bisa tiba sebagai beberapa recv()
atau beberapa send() bisa tergabung. Prefix panjang membuat penerima tahu
persis berapa byte yang harus dibaca untuk satu pesan utuh.

Jenis payload:
    Mode DES (default) : {"seq": 1, "iv": "<hex>", "ciphertext": "<hex>"}
    Mode plain (demo)  : {"seq": 1, "plaintext": "<teks>"}
    Kontrol keluar     : {"type": "bye"}

Key TIDAK PERNAH menjadi bagian dari payload.
"""

import json
import struct

HEADER = struct.Struct(">I")      # unsigned int 32-bit, big-endian
MAX_FRAME_SIZE = 1024 * 1024      # batas 1 MiB agar tidak bisa dibanjiri

MODE_DES = "des"
MODE_PLAIN = "plain"


class ProtocolError(Exception):
    """Frame tidak valid (JSON rusak, terlalu besar, format salah)."""


class ConnectionClosed(Exception):
    """Lawan bicara menutup koneksi."""


# ---------------------------------------------------------------------------
# Pembuatan payload
# ---------------------------------------------------------------------------

def make_des_payload(seq, iv, ciphertext):
    return {"seq": seq, "iv": iv.hex().upper(), "ciphertext": ciphertext.hex().upper()}


def make_plain_payload(seq, plaintext):
    return {"seq": seq, "plaintext": plaintext}


def make_bye_payload():
    return {"type": "bye"}


def detect_mode(payload):
    """Kembalikan MODE_DES / MODE_PLAIN / 'bye', atau lempar ProtocolError."""
    if not isinstance(payload, dict):
        raise ProtocolError("Payload bukan objek JSON")
    if payload.get("type") == "bye":
        return "bye"
    if "ciphertext" in payload and "iv" in payload:
        return MODE_DES
    if "plaintext" in payload:
        return MODE_PLAIN
    raise ProtocolError("Format payload tidak dikenali")


# ---------------------------------------------------------------------------
# Encode / decode frame
# ---------------------------------------------------------------------------

def encode_frame(payload):
    """dict -> bytes (header panjang + JSON)."""
    # ensure_ascii=False agar teks mode plain terbaca apa adanya di Wireshark.
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_SIZE:
        raise ProtocolError("Pesan terlalu besar")
    return HEADER.pack(len(body)) + body


def decode_body(body):
    """bytes JSON -> dict."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Payload JSON tidak valid") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("Payload bukan objek JSON")
    return payload


# ---------------------------------------------------------------------------
# Socket I/O
# ---------------------------------------------------------------------------

def recv_exact(sock, n):
    """
    Baca tepat n byte. recv() boleh mengembalikan lebih sedikit dari yang
    diminta (partial recv), jadi diulang sampai lengkap.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionClosed("Koneksi ditutup oleh peer")
        buf += chunk
    return bytes(buf)


def send_message(sock, payload):
    """Kirim satu frame. sendall() memastikan semua byte terkirim."""
    frame = encode_frame(payload)
    sock.sendall(frame)
    return frame


def recv_message(sock):
    """Terima satu frame utuh dan kembalikan dict payload."""
    (length,) = HEADER.unpack(recv_exact(sock, HEADER.size))
    if length > MAX_FRAME_SIZE:
        raise ProtocolError("Frame terlalu besar (%d byte)" % length)
    return decode_body(recv_exact(sock, length))
