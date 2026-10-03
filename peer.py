"""
peer.py - Chat terenkripsi DES-CBC dua arah antara dua proses lewat TCP.

Contoh:
    Terminal 1:  python peer.py --listen --name Alice
    Terminal 2:  python peer.py --connect 127.0.0.1 --name Bob

Key dibaca dari shared_key.txt (atau --key / --key-file) dan sudah dimiliki
kedua pihak sebelumnya. Key TIDAK PERNAH dikirim lewat jaringan.
"""

import argparse
import logging
import os
import socket
import sys
import threading
from datetime import datetime

from modes import DecryptionError, cbc_decrypt, cbc_encrypt
from protocol import (
    MODE_DES,
    MODE_PLAIN,
    ConnectionClosed,
    ProtocolError,
    detect_mode,
    make_bye_payload,
    make_des_payload,
    make_plain_payload,
    recv_message,
    send_message,
)

DEFAULT_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shared_key.txt")
QUIT_COMMAND = "/quit"


# ---------------------------------------------------------------------------
# Tampilan terminal
# ---------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


class Console:
    """Output terminal yang thread-safe, opsional disalin ke file log."""

    def __init__(self, name, use_color=True, log_file=None):
        self.name = name
        self.use_color = use_color
        self.lock = threading.Lock()
        self.logger = None
        if log_file:
            self.logger = logging.getLogger("peer")
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def _c(self, color, text):
        return f"{color}{text}{Color.RESET}" if self.use_color else text

    def emit(self, tag, color, header, fields=()):
        """
        Cetak satu entri berformat:
            [YYYY-mm-dd HH:MM:SS] [Nama] [TAG ] header
                field      : nilai
        """
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain_lines = [f"[{ts}] [{self.name}] [{tag:<4}] {header}"]
        color_lines = [
            f"{self._c(Color.GREY, '[' + ts + ']')} "
            f"{self._c(Color.BOLD, '[' + self.name + ']')} "
            f"{self._c(color + Color.BOLD, '[' + format(tag, '<4') + ']')} {header}"
        ]
        for label, value in fields:
            line = f"    {label:<11}: {value}"
            plain_lines.append(line)
            color_lines.append(f"    {self._c(Color.GREY, format(label, '<11') + ':')} {value}")
        with self.lock:
            print("\n".join(color_lines), flush=True)
            if self.logger:
                self.logger.info("\n".join(plain_lines))

    def info(self, msg):
        self.emit("INFO", Color.CYAN, msg)

    def warn(self, msg, fields=()):
        self.emit("WARN", Color.YELLOW, msg, fields)

    def error(self, msg, fields=()):
        self.emit("ERR", Color.RED, msg, fields)

    def banner(self, lines, color):
        width = max(len(l) for l in lines) + 4
        border = "!" * width
        with self.lock:
            print(self._c(color + Color.BOLD, border))
            for l in lines:
                print(self._c(color + Color.BOLD, f"! {l:<{width - 4}} !"))
            print(self._c(color + Color.BOLD, border), flush=True)


def enable_windows_ansi():
    """Aktifkan dukungan escape code ANSI di konsol Windows 10+."""
    if os.name == "nt":
        os.system("")


# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------

class KeyFormatError(ValueError):
    pass


def parse_key_hex(text):
    """Validasi key: tepat 16 karakter hex (8 byte). Pesan error tidak memuat key."""
    cleaned = text.strip().replace(" ", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 16:
        raise KeyFormatError(f"Key harus tepat 16 karakter hex (8 byte), didapat {len(cleaned)} karakter")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise KeyFormatError("Key mengandung karakter non-hex (hanya 0-9 dan A-F)") from None


def load_key_file(path):
    """Baca key dari file. Baris kosong dan baris diawali '#' diabaikan."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except OSError as exc:
        raise KeyFormatError(f"Tidak bisa membaca file key '{path}': {exc.strerror}") from None
    if len(lines) != 1:
        raise KeyFormatError(f"File key '{path}' harus berisi tepat satu baris key hex")
    return parse_key_hex(lines[0])


# ---------------------------------------------------------------------------
# Peer
# ---------------------------------------------------------------------------

class Peer:
    def __init__(self, sock, key, mode, console):
        self.sock = sock
        self.key = key
        self.mode = mode
        self.console = console
        self.seq = 0
        self.send_lock = threading.Lock()
        self.stop = threading.Event()
        try:
            self.remote = "%s:%d" % sock.getpeername()[:2]
        except OSError:
            self.remote = "peer"

    # ----- pengiriman -----

    def send_text(self, text):
        with self.send_lock:
            self.seq += 1
            seq = self.seq
            if self.mode == MODE_DES:
                iv, ct = cbc_encrypt(self.key, text.encode("utf-8"))
                payload = make_des_payload(seq, iv, ct)
                send_message(self.sock, payload)
                self.console.emit("SEND", Color.GREEN, f"seq={seq} -> {self.remote}", [
                    ("plaintext", text),
                    ("iv", payload["iv"]),
                    ("ciphertext", payload["ciphertext"]),
                    ("panjang", f"{len(ct)} byte ciphertext ({len(ct) // 8} blok)"),
                ])
            else:
                send_message(self.sock, make_plain_payload(seq, text))
                self.console.emit("SEND", Color.YELLOW, f"seq={seq} -> {self.remote}  (TANPA ENKRIPSI)", [
                    ("plaintext", text),
                ])

    def send_loop(self):
        """Thread pengirim: baca input user, enkripsi, kirim."""
        try:
            while not self.stop.is_set():
                try:
                    line = input()
                except EOFError:
                    line = QUIT_COMMAND
                if self.stop.is_set():
                    break
                text = line.rstrip("\r\n")
                if text.strip() == QUIT_COMMAND:
                    self.console.info("Keluar... memberi tahu peer.")
                    try:
                        send_message(self.sock, make_bye_payload())
                    except OSError:
                        pass
                    break
                if not text:
                    continue
                self.send_text(text)
        except OSError as exc:
            if not self.stop.is_set():
                self.console.error(f"Gagal mengirim: koneksi terputus ({exc.__class__.__name__})")
        finally:
            self.stop.set()

    # ----- penerimaan -----

    def handle_payload(self, payload):
        try:
            mode = detect_mode(payload)
        except ProtocolError as exc:
            self.console.error(f"Payload tidak dikenali: {exc}")
            return True
        if mode == "bye":
            self.console.info(f"Peer {self.remote} keluar dari percakapan.")
            return False

        seq = payload.get("seq", "?")
        if mode != self.mode:
            self.console.error(
                f"Mode tidak cocok pada seq={seq}: peer mengirim mode {mode.upper()}, "
                f"sedangkan peer ini mode {self.mode.upper()}.",
                [("solusi", "Jalankan kedua peer dengan mode yang sama (keduanya pakai --plain, "
                            "atau keduanya tanpa --plain).")],
            )
            return True

        if mode == MODE_PLAIN:
            self.console.emit("RECV", Color.YELLOW, f"seq={seq} <- {self.remote}  (TANPA ENKRIPSI)", [
                ("plaintext", payload.get("plaintext")),
            ])
            return True

        iv_hex = str(payload.get("iv", ""))
        ct_hex = str(payload.get("ciphertext", ""))
        fields = [("iv", iv_hex), ("ciphertext", ct_hex)]
        try:
            pt = cbc_decrypt(self.key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex))
            text = pt.decode("utf-8")
        except (DecryptionError, ValueError):
            # ValueError mencakup hex tidak valid & UnicodeDecodeError.
            self.console.error(f"seq={seq} <- {self.remote}  Dekripsi gagal (key salah atau data rusak)", fields)
            return True
        self.console.emit("RECV", Color.CYAN, f"seq={seq} <- {self.remote}", fields + [("plaintext", text)])
        return True

    def recv_loop(self):
        """Thread penerima: terima frame, dekripsi, tampilkan."""
        try:
            while not self.stop.is_set():
                try:
                    payload = recv_message(self.sock)
                except ProtocolError as exc:
                    self.console.error(f"Frame rusak dari peer: {exc}. Koneksi ditutup.")
                    break
                if not self.handle_payload(payload):
                    break
        except ConnectionClosed:
            if not self.stop.is_set():
                self.console.warn("Koneksi ditutup oleh peer.")
        except OSError as exc:
            if not self.stop.is_set():
                self.console.warn(f"Koneksi terputus ({exc.__class__.__name__}).")
        finally:
            self.stop.set()

    def run(self):
        threading.Thread(target=self.recv_loop, name="receiver", daemon=True).start()
        # Input dibaca di thread daemon agar main thread bisa keluar dengan rapi
        # saat peer menutup koneksi walaupun input() masih menunggu.
        threading.Thread(target=self.send_loop, name="sender", daemon=True).start()
        try:
            while not self.stop.wait(0.2):
                pass
        except KeyboardInterrupt:
            self.console.info("Ctrl+C ditekan, keluar...")
            try:
                send_message(self.sock, make_bye_payload())
            except OSError:
                pass
            self.stop.set()
        finally:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.console.info("Koneksi ditutup. Sampai jumpa!")


# ---------------------------------------------------------------------------
# Koneksi
# ---------------------------------------------------------------------------

def open_listen(host, port, console):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name != "nt":
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(0.5)  # agar Ctrl+C tetap bisa menghentikan accept() di Windows
    console.info(f"Menunggu koneksi di {host}:{port} ...")
    try:
        while True:
            try:
                conn, addr = srv.accept()
                break
            except socket.timeout:
                continue
    finally:
        srv.close()
    conn.settimeout(None)
    console.info(f"Terhubung dengan {addr[0]}:{addr[1]}")
    return conn


def open_connect(host, port, console):
    console.info(f"Menyambung ke {host}:{port} ...")
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(None)
    console.info(f"Terhubung dengan {host}:{port}")
    return sock


def build_parser():
    p = argparse.ArgumentParser(
        description="Peer chat terenkripsi DES-CBC (implementasi manual) lewat TCP.",
    )
    role = p.add_mutually_exclusive_group(required=True)
    role.add_argument("--listen", action="store_true", help="tunggu koneksi masuk")
    role.add_argument("--connect", metavar="HOST", help="sambung ke peer di HOST")
    p.add_argument("--host", default="0.0.0.0", help="alamat bind untuk --listen (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=5000, help="port TCP (default 5000)")
    keygrp = p.add_mutually_exclusive_group()
    keygrp.add_argument("--key", metavar="HEX", help="key DES 16 karakter hex")
    keygrp.add_argument("--key-file", metavar="PATH", help="file berisi key hex (default shared_key.txt)")
    p.add_argument("--name", default=None, help="label peer, misal Alice / Bob")
    p.add_argument("--plain", action="store_true",
                   help="kirim TANPA enkripsi (hanya untuk pembanding demo Wireshark)")
    p.add_argument("--log", metavar="FILE", help="simpan salinan output ke file log")
    p.add_argument("--no-color", action="store_true", help="matikan warna ANSI")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    enable_windows_ansi()
    name = args.name or ("Listener" if args.listen else "Connector")
    console = Console(name, use_color=not args.no_color, log_file=args.log)

    mode = MODE_PLAIN if args.plain else MODE_DES
    key = None
    if mode == MODE_DES:
        try:
            if args.key:
                key = parse_key_hex(args.key)
                source = "argumen --key"
            else:
                path = args.key_file or DEFAULT_KEY_FILE
                key = load_key_file(path)
                source = f"file {os.path.basename(path)}"
        except KeyFormatError as exc:
            console.error(f"Key tidak valid: {exc}")
            return 2
        # Isi key sengaja tidak pernah dicetak.
        console.info(f"Mode: DES-CBC | key 8 byte dimuat dari {source} (tidak dikirim lewat jaringan)")
    else:
        console.banner([
            "PERINGATAN: MODE --plain AKTIF",
            "Pesan dikirim TANPA ENKRIPSI dan bisa dibaca siapa pun",
            "yang menyadap jaringan (misal Wireshark).",
            "Gunakan HANYA sebagai pembanding demo.",
        ], Color.RED)

    try:
        if args.listen:
            sock = open_listen(args.host, args.port, console)
        else:
            sock = open_connect(args.connect, args.port, console)
    except KeyboardInterrupt:
        console.info("Dibatalkan.")
        return 1
    except OSError as exc:
        console.error(f"Gagal membuka koneksi: {exc.strerror or exc}")
        if args.connect:
            console.info("Pastikan peer lain sudah berjalan dengan --listen dan port/firewall terbuka.")
        return 1

    console.info(f"Ketik pesan lalu Enter untuk mengirim. Ketik {QUIT_COMMAND} untuk keluar.")
    Peer(sock, key, mode, console).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
