# Chat Terenkripsi DES-CBC Dua Arah (Implementasi Manual)

Tugas individu mata kuliah **Keamanan Informasi**: simulasi transmisi ciphertext
dua arah antara dua proses terpisah (Peer A dan Peer B) lewat TCP. Setiap peer
bisa mengirim sekaligus menerima, mirip aplikasi chat terenkripsi.

- Algoritma: **DES**, diimplementasikan manual sepenuhnya ([des.py](des.py)).
- Mode operasi: **CBC** dengan IV acak per pesan + padding **PKCS#7** ([modes.py](modes.py)).
- Key: **pre-shared** 8 byte, sudah dimiliki kedua pihak, **tidak pernah dikirim**.
- Hanya memakai Python 3 standard library.

> **Pernyataan:** proyek ini **tidak memakai library kriptografi apa pun**
> (tidak ada `cryptography`, `pycryptodome`, `pyDes`, `hashlib`, `ssl`, OpenSSL, dll),
> termasuk di dalam test. Satu-satunya fungsi bawaan yang dipakai terkait keacakan
> adalah `os.urandom`, hanya untuk membangkitkan IV.

---

## 1. Alur DES yang diimplementasikan

```
           Key 64 bit                          Plaintext 64 bit
               │                                      │
            [PC-1]  buang 8 bit paritas → 56 bit    [IP]  Initial Permutation
               │                                      │
         C0 (28) | D0 (28)                       L0 (32) | R0 (32)
               │                                      │
   ronde i: rotasi kiri C,D (1 atau 2 bit)      ┌─────┴─────────────────────┐
            [PC-2] → subkey K_i (48 bit) ─────► │ 16 ronde Feistel:          │
                                                │  L_i = R_{i-1}             │
                                                │  R_i = L_{i-1} ⊕ f(R_{i-1},K_i)
                                                └─────┬─────────────────────┘
                                                      │
                                              swap → R16 | L16
                                                      │
                                                  [IP⁻¹]  Final Permutation
                                                      │
                                               Ciphertext 64 bit
```

**Fungsi Feistel f(R, K):**

1. **Ekspansi E**: R 32 bit → 48 bit (beberapa bit diduplikasi).
2. **XOR** dengan subkey K_i (48 bit).
3. **8 S-box**: setiap potongan 6 bit → 4 bit (baris = bit ke-1 & ke-6, kolom = bit ke-2..5). Ini satu-satunya bagian non-linear di DES.
4. **Permutasi P** pada 32 bit hasil S-box.

**Key schedule:** PC-1 → bagi C/D → untuk setiap ronde rotasi kiri sesuai tabel
`SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]` → PC-2 → 16 subkey 48 bit.

**Dekripsi:** algoritma yang sama persis, hanya urutan subkey dibalik (K16 … K1).

### CBC + PKCS#7

```
Enkripsi:  C_1 = E_K(P_1 ⊕ IV)        Dekripsi:  P_1 = D_K(C_1) ⊕ IV
           C_i = E_K(P_i ⊕ C_{i-1})              P_i = D_K(C_i) ⊕ C_{i-1}
```

- **PKCS#7**: tambahkan N byte bernilai N (1–8). Pesan yang panjangnya sudah kelipatan 8 tetap ditambah satu blok penuh `08 08 … 08`. Saat unpad, nilai dan konsistensi semua byte padding divalidasi; kegagalan validasi berarti key salah atau data rusak.
- **IV** 8 byte acak dibangkitkan untuk setiap pesan dan dikirim terbuka. IV bukan rahasia; fungsinya membuat pesan identik menghasilkan ciphertext berbeda.

## 2. Alur komunikasi

```
   ┌──────────────── Peer A (Alice) ───────────────┐                     ┌──────────────── Peer B (Bob) ─────────────────┐
   │  shared_key.txt  ── KEY (sudah dimiliki) ──┐  │                     │  ┌── KEY (sudah dimiliki) ──  shared_key.txt  │
   │                                            │  │                     │  │                                            │
   │  input "Halo"                              ▼  │                     │  ▼                                            │
   │    → PKCS#7 pad → DES-CBC(KEY, IV acak)       │   TCP (port 5000)   │      DES-CBC⁻¹(KEY, IV) → unpad → "Halo"      │
   │    → {"seq":1,"iv":"…","ciphertext":"…"} ─────┼────────────────────►┼──── [RECV] tampilkan                          │
   │                                               │                     │                                               │
   │  [RECV] "Hai"  ◄──── DES-CBC⁻¹ ◄──────────────┼◄────────────────────┼──── {"seq":1,"iv":"…","ciphertext":"…"}      │
   │                                               │                     │      ◄── DES-CBC(KEY, IV acak) ◄── input "Hai"│
   └───────────────────────────────────────────────┘                     └───────────────────────────────────────────────┘

        Yang lewat di jaringan :  panjang (4 byte) + JSON { seq, iv, ciphertext }
        Yang TIDAK lewat       :  KEY  (dibagikan offline sebelumnya, tidak pernah ditransmisikan)
        IV                     :  dikirim terbuka (bukan rahasia)
```

Setiap peer menjalankan **dua thread**:

- **Pengirim**: membaca input keyboard → enkripsi → kirim.
- **Penerima**: menerima frame → dekripsi → tampilkan.

### Format frame (protocol.py)

```
+-----------------------------+----------------------------------------------------+
| panjang payload (4 byte BE) | payload JSON UTF-8                                 |
+-----------------------------+----------------------------------------------------+
Mode DES   : {"seq":1,"iv":"86157D74185FB268","ciphertext":"F48E4DE8F5DD7876..."}
Mode plain : {"seq":1,"plaintext":"Halo Bob"}        ← hanya pembanding demo
Keluar     : {"type":"bye"}                          ← dikirim saat /quit
```

Penerima selalu membaca tepat 4 byte header lalu tepat N byte payload. Partial
recv ditangani dengan loop sampai lengkap, dan koneksi terputus dideteksi
saat `recv()` mengembalikan 0 byte.

## 3. Struktur proyek

```
.
├── des.py               # DES murni: tabel IP, IP⁻¹, E, P, PC-1, PC-2, S-box, key schedule, Feistel
├── modes.py             # PKCS#7 pad/unpad + CBC encrypt/decrypt
├── protocol.py          # Framing TCP (length-prefix + JSON), recv_exact, deteksi mode
├── peer.py              # Program peer: --listen / --connect, dua thread kirim & terima
├── shared_key.txt       # Contoh pre-shared key (16 karakter hex)
├── tests/
│   ├── test_des.py      # Test vector DES, PKCS#7, CBC round-trip, IV acak, key salah
│   └── test_protocol.py # Framing, partial recv, koneksi terputus, transmisi TCP nyata
├── README.md
└── WIRESHARK_DEMO.md    # Panduan demo capture paket
```

## 4. Cara menjalankan

Butuh **Python 3.8+**. Tidak ada dependensi yang perlu dipasang.

### Opsi argumen

| Argumen | Keterangan |
|---|---|
| `--listen` | Menunggu koneksi masuk (jadi "server"). |
| `--connect HOST` | Menyambung ke peer di `HOST`. |
| `--host` | Alamat bind untuk `--listen` (default `0.0.0.0`). |
| `--port` | Port TCP (default `5000`). |
| `--key HEX` | Key 16 karakter hex, sebagai pengganti file. |
| `--key-file PATH` | File key (default `shared_key.txt`). |
| `--name` | Label peer di log, misal `Alice` / `Bob`. |
| `--plain` | Kirim **tanpa enkripsi**, hanya untuk pembanding Wireshark. |
| `--log FILE` | Simpan salinan output ke file (key tidak pernah ditulis). |
| `--no-color` | Matikan warna terminal. |

Ketik pesan lalu **Enter** untuk mengirim. Ketik **`/quit`** untuk keluar; peer
lawan akan diberi tahu dan ikut menutup koneksi dengan rapi.

### a. Satu laptop, dua terminal

```bash
# Terminal 1
python peer.py --listen --name Alice

# Terminal 2
python peer.py --connect 127.0.0.1 --name Bob
```

(Di Linux/macOS gunakan `python3` jika `python` belum mengarah ke Python 3.)

### b. Dua VM (VirtualBox / VMware)

1. Set network adapter kedua VM ke **Bridged Adapter**, **Host-only**, atau **NAT Network** (bukan NAT biasa, karena NAT biasa membuat VM tidak saling terlihat).
2. Salin folder proyek (termasuk `shared_key.txt` yang **sama**) ke kedua VM.
3. Cek IP VM A: `ip a` (Linux) atau `ipconfig` (Windows), misal `192.168.56.101`.
4. Buka port di firewall VM A (lihat bagian firewall di bawah).
5. Jalankan:
   ```bash
   # VM A
   python3 peer.py --listen --name Alice
   # VM B
   python3 peer.py --connect 192.168.56.101 --name Bob
   ```
6. Uji konektivitas jika gagal: `ping 192.168.56.101`.

### c. Dua komputer dalam satu jaringan (Wi-Fi/LAN yang sama)

1. **Cek IP** komputer A:
   - Windows: `ipconfig` → lihat *IPv4 Address* pada adapter Wi-Fi/Ethernet.
   - Linux: `ip a` atau `hostname -I`.
   - macOS: `ipconfig getifaddr en0`.
2. **Buka port 5000** di komputer A:
   - Windows (PowerShell sebagai Administrator):
     ```powershell
     netsh advfirewall firewall add rule name="DES Chat 5000" dir=in action=allow protocol=TCP localport=5000
     ```
     Atau klik **Allow access** saat muncul pop-up Windows Defender Firewall untuk Python.
     Hapus aturan setelah demo:
     `netsh advfirewall firewall delete rule name="DES Chat 5000"`
   - Linux (ufw): `sudo ufw allow 5000/tcp`
3. Pastikan `shared_key.txt` di kedua komputer **sama persis** (dibagikan lewat flashdisk/chat terpisah, bukan lewat program ini).
4. Jalankan:
   ```bash
   # Komputer A
   python peer.py --listen --name Alice
   # Komputer B
   python peer.py --connect 192.168.1.10 --name Bob
   ```

> Catatan: Wi-Fi publik/kampus sering mengaktifkan *client isolation* sehingga
> antarperangkat tidak bisa saling terhubung. Gunakan hotspot HP jika ini terjadi.

## 5. Menjalankan test

```bash
python -m unittest discover -s tests -v
```

Test mencakup:

- Test vector DES standar: `133457799BBCDFF1` / `0123456789ABCDEF` → `85E813540F0AB405`, `0E329232EA6D0D73` / `8787878787878787` → `0000000000000000`, dan key nol / plaintext nol → `8CA64DE9C1B123A7`. Subkey K1 juga dicocokkan dengan contoh literatur.
- Round-trip CBC untuk pesan kosong, 1 byte, 8 byte, 16 byte, panjang, serta UTF-8 (emoji, huruf Indonesia, aksen).
- Pesan identik → IV & ciphertext berbeda.
- Key salah / ciphertext rusak → `DecryptionError` (tertangani, bukan crash).
- Framing: encode/decode, pesan diterima **byte per byte** dan potongan acak, beberapa frame dalam satu buffer, koneksi putus di tengah header/body, JSON rusak, frame terlalu besar.
- Transmisi nyata lewat socket TCP localhost.
- Payload jaringan tidak memuat key.

## 6. Contoh output demo

**Peer A (Alice, `--listen`)**

```
[2026-10-01 19:54:27] [Alice] [INFO] Mode: DES-CBC | key 8 byte dimuat dari file shared_key.txt (tidak dikirim lewat jaringan)
[2026-10-01 19:54:27] [Alice] [INFO] Menunggu koneksi di 0.0.0.0:5000 ...
[2026-10-01 19:54:28] [Alice] [INFO] Terhubung dengan 127.0.0.1:63271
[2026-10-01 19:54:28] [Alice] [INFO] Ketik pesan lalu Enter untuk mengirim. Ketik /quit untuk keluar.
[2026-10-01 19:54:29] [Alice] [SEND] seq=1 -> 127.0.0.1:63271
    plaintext  : Halo Bob, ini Alice
    iv         : 90AE4C2A83990E8B
    ciphertext : E636B961105DCAA6EDAF219056F78A851CF0C0FA32045BAA
    panjang    : 24 byte ciphertext (3 blok)
[2026-10-01 19:54:30] [Alice] [SEND] seq=2 -> 127.0.0.1:63271
    plaintext  : Pesan sama
    iv         : 6348BA5ADB29F145
    ciphertext : 54EB6C2091584151D773D238DC2DA4E6
    panjang    : 16 byte ciphertext (2 blok)
[2026-10-01 19:54:30] [Alice] [RECV] seq=1 <- 127.0.0.1:63271
    iv         : 51BAC2B8CD8D43F1
    ciphertext : 2482C98A5F9A8D2BB062375A98365207BDB540397AD2A8BEFB03349E7EA4F9289C8CA588450EA0712D5CC2E205AB8E8CE40F6C86B30F97D8
    plaintext  : Halo Alice 👋 apa kabar? Saya Bob dari Jakarta
[2026-10-01 19:54:30] [Alice] [SEND] seq=3 -> 127.0.0.1:63271
    plaintext  : Pesan sama
    iv         : 72471C0DDBCA258E
    ciphertext : 01191B02E70CA61AD82BA4146D3B2A08
    panjang    : 16 byte ciphertext (2 blok)
[2026-10-01 19:54:32] [Alice] [INFO] Peer 127.0.0.1:63271 keluar dari percakapan.
[2026-10-01 19:54:32] [Alice] [INFO] Koneksi ditutup. Sampai jumpa!
```

**Peer B (Bob, `--connect`)**

```
[2026-10-01 19:54:28] [Bob] [INFO] Mode: DES-CBC | key 8 byte dimuat dari file shared_key.txt (tidak dikirim lewat jaringan)
[2026-10-01 19:54:28] [Bob] [INFO] Menyambung ke 127.0.0.1:5000 ...
[2026-10-01 19:54:28] [Bob] [INFO] Terhubung dengan 127.0.0.1:5000
[2026-10-01 19:54:29] [Bob] [RECV] seq=1 <- 127.0.0.1:5000
    iv         : 90AE4C2A83990E8B
    ciphertext : E636B961105DCAA6EDAF219056F78A851CF0C0FA32045BAA
    plaintext  : Halo Bob, ini Alice
[2026-10-01 19:54:30] [Bob] [RECV] seq=2 <- 127.0.0.1:5000
    iv         : 6348BA5ADB29F145
    ciphertext : 54EB6C2091584151D773D238DC2DA4E6
    plaintext  : Pesan sama
[2026-10-01 19:54:30] [Bob] [SEND] seq=1 -> 127.0.0.1:5000
    plaintext  : Halo Alice 👋 apa kabar? Saya Bob dari Jakarta
    iv         : 51BAC2B8CD8D43F1
    ciphertext : 2482C98A5F9A8D2BB062375A98365207BDB540397AD2A8BEFB03349E7EA4F9289C8CA588450EA0712D5CC2E205AB8E8CE40F6C86B30F97D8
    panjang    : 56 byte ciphertext (7 blok)
[2026-10-01 19:54:30] [Bob] [RECV] seq=3 <- 127.0.0.1:5000
    iv         : 72471C0DDBCA258E
    ciphertext : 01191B02E70CA61AD82BA4146D3B2A08
    plaintext  : Pesan sama
[2026-10-01 19:54:32] [Bob] [INFO] Keluar... memberi tahu peer.
[2026-10-01 19:54:32] [Bob] [INFO] Koneksi ditutup. Sampai jumpa!
```

Perhatikan bahwa `seq=2` dan `seq=3` membawa plaintext yang sama (`Pesan sama`)
tetapi IV dan ciphertext-nya berbeda.

**Key salah** (Bob memakai `--key 0E329232EA6D0D73`), program tetap berjalan:

```
[2026-10-01 19:55:14] [Bob] [ERR ] seq=1 <- 127.0.0.1:5000  Dekripsi gagal (key salah atau data rusak)
    iv         : F794741A26620CC4
    ciphertext : 058505FC795BF2466EB7203A97670331
```

**Mode tidak cocok** (Alice DES, Bob `--plain`):

```
[2026-10-01 19:55:21] [Alice] [ERR ] Mode tidak cocok pada seq=1: peer mengirim mode PLAIN, sedangkan peer ini mode DES.
    solusi     : Jalankan kedua peer dengan mode yang sama (keduanya pakai --plain, atau keduanya tanpa --plain).
```

**Key tidak valid:**

```
[2026-10-01 19:55:09] [Listener] [ERR ] Key tidak valid: Key harus tepat 16 karakter hex (8 byte), didapat 4 karakter
```

## 7. Demo Wireshark

Langkah lengkap capture paket, mulai dari perbandingan mode plain vs DES, efek IV
acak, komunikasi dua arah, hingga bukti bahwa key tidak ada di jaringan, ada di
**[WIRESHARK_DEMO.md](WIRESHARK_DEMO.md)**.

## 8. Catatan keamanan

DES (key efektif 56 bit) sudah **tidak aman** untuk penggunaan nyata dan bisa
di-brute-force. Proyek ini juga tidak memakai MAC/autentikasi pesan, sehingga
penyerang aktif bisa memodifikasi ciphertext (yang akan terdeteksi hanya jika
padding menjadi rusak). Implementasi ini dibuat untuk tujuan **pembelajaran**.
