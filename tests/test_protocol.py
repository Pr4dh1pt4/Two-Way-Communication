"""Pengujian framing protokol, termasuk pesan yang diterima terpotong-potong."""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modes import cbc_decrypt, cbc_encrypt  # noqa: E402
from protocol import (  # noqa: E402
    MAX_FRAME_SIZE,
    MODE_DES,
    MODE_PLAIN,
    ConnectionClosed,
    ProtocolError,
    decode_body,
    detect_mode,
    encode_frame,
    make_bye_payload,
    make_des_payload,
    make_plain_payload,
    recv_message,
    send_message,
)

KEY = bytes.fromhex("133457799BBCDFF1")


class FakeSocket:
    """Socket tiruan yang mengembalikan data dalam potongan-potongan kecil."""

    def __init__(self, data, chunk_sizes):
        self.data = data
        self.pos = 0
        self.chunk_sizes = list(chunk_sizes)

    def recv(self, n):
        size = self.chunk_sizes.pop(0) if self.chunk_sizes else n
        size = min(size, n, len(self.data) - self.pos)
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk


class TestFraming(unittest.TestCase):
    def test_encode_header(self):
        frame = encode_frame({"seq": 1})
        body = b'{"seq":1}'
        self.assertEqual(frame[:4], len(body).to_bytes(4, "big"))
        self.assertEqual(frame[4:], body)

    def test_encode_decode_roundtrip(self):
        payloads = [
            make_plain_payload(1, "Halo Bob 👋, apa kabar?"),
            make_des_payload(2, bytes(8), bytes.fromhex("85E813540F0AB405")),
            make_bye_payload(),
        ]
        for p in payloads:
            with self.subTest(p=p):
                frame = encode_frame(p)
                self.assertEqual(recv_message(FakeSocket(frame, [])), p)
                self.assertEqual(decode_body(frame[4:]), p)

    def test_partial_recv_one_byte_at_a_time(self):
        p = make_plain_payload(7, "pesan dikirim byte per byte")
        frame = encode_frame(p)
        self.assertEqual(recv_message(FakeSocket(frame, [1] * len(frame))), p)

    def test_partial_recv_irregular_chunks(self):
        p = make_des_payload(3, os.urandom(8), os.urandom(64))
        frame = encode_frame(p)
        self.assertEqual(recv_message(FakeSocket(frame, [2, 1, 3, 5, 7, 1, 11])), p)

    def test_multiple_frames_in_one_buffer(self):
        p1 = make_plain_payload(1, "satu")
        p2 = make_plain_payload(2, "dua")
        sock = FakeSocket(encode_frame(p1) + encode_frame(p2), [3, 100, 2])
        self.assertEqual(recv_message(sock), p1)
        self.assertEqual(recv_message(sock), p2)

    def test_connection_closed_in_header(self):
        with self.assertRaises(ConnectionClosed):
            recv_message(FakeSocket(b"\x00\x00", []))

    def test_connection_closed_in_body(self):
        frame = encode_frame(make_plain_payload(1, "terpotong"))
        with self.assertRaises(ConnectionClosed):
            recv_message(FakeSocket(frame[:-3], []))

    def test_connection_closed_empty(self):
        with self.assertRaises(ConnectionClosed):
            recv_message(FakeSocket(b"", []))

    def test_invalid_json(self):
        body = b"{bukan json"
        with self.assertRaises(ProtocolError):
            recv_message(FakeSocket(len(body).to_bytes(4, "big") + body, []))

    def test_frame_too_large(self):
        with self.assertRaises(ProtocolError):
            recv_message(FakeSocket((MAX_FRAME_SIZE + 1).to_bytes(4, "big"), []))

    def test_detect_mode(self):
        self.assertEqual(detect_mode(make_des_payload(1, bytes(8), bytes(8))), MODE_DES)
        self.assertEqual(detect_mode(make_plain_payload(1, "x")), MODE_PLAIN)
        self.assertEqual(detect_mode(make_bye_payload()), "bye")
        with self.assertRaises(ProtocolError):
            detect_mode({"seq": 1})

    def test_des_payload_has_no_key(self):
        iv, ct = cbc_encrypt(KEY, b"rahasia")
        frame = encode_frame(make_des_payload(1, iv, ct))
        self.assertNotIn(KEY.hex().upper().encode(), frame.upper())
        self.assertNotIn(KEY, frame)
        self.assertEqual(set(make_des_payload(1, iv, ct)), {"seq", "iv", "ciphertext"})


class TestRealSocket(unittest.TestCase):
    """Transmisi nyata lewat socket TCP localhost antara dua thread."""

    def test_des_over_tcp(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received = []

        def receiver():
            conn, _ = server.accept()
            with conn:
                for _ in range(3):
                    received.append(recv_message(conn))

        t = threading.Thread(target=receiver)
        t.start()
        messages = ["Halo", "Pesan kedua 🔐", "x" * 5000]
        with socket.create_connection(("127.0.0.1", port)) as client:
            for i, m in enumerate(messages, 1):
                iv, ct = cbc_encrypt(KEY, m.encode("utf-8"))
                send_message(client, make_des_payload(i, iv, ct))
        t.join(5)
        server.close()

        self.assertEqual(len(received), 3)
        for i, (p, m) in enumerate(zip(received, messages), 1):
            self.assertEqual(p["seq"], i)
            pt = cbc_decrypt(KEY, bytes.fromhex(p["iv"]), bytes.fromhex(p["ciphertext"]))
            self.assertEqual(pt.decode("utf-8"), m)


if __name__ == "__main__":
    unittest.main()
