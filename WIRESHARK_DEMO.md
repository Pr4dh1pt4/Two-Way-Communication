# Panduan Demo Wireshark

Panduan ini menunjukkan, lewat capture paket nyata, bahwa:

1. Mode `--plain` mengirim teks yang bisa dibaca siapa pun.
2. Mode DES hanya mengirim **IV dan ciphertext**.
3. Pesan identik menghasilkan ciphertext berbeda karena IV acak (CBC).
4. Komunikasi berjalan dua arah (A→B dan B→A).
5. **Key tidak pernah ada di jaringan.**

> **Tips penting:** mulai capture **SEBELUM** kedua peer saling terhubung, supaya
> TCP 3-way handshake (SYN, SYN-ACK, ACK) ikut terekam.

---

## 1. Memilih interface yang benar

| Skenario | Interface yang dipilih di Wireshark |
|---|---|
| Satu laptop, dua terminal (`127.0.0.1`) | **Linux:** `lo` (Loopback). **Windows:** *Adapter for loopback traffic capture* (Npcap Loopback Adapter). Pastikan Npcap terpasang dengan opsi loopback saat instalasi Wireshark. |
| Dua VM atau dua komputer | Interface jaringan yang dipakai peer: **Wi-Fi** atau **Ethernet** (di VM biasanya `eth0`/`enp0s3`). Capture di salah satu komputer peer. |

Lalu klik dua kali interface tersebut (atau tombol sirip hiu biru) untuk mulai capture.

## 2. Filter dan Follow TCP Stream

1. Di kolom **display filter** (atas), ketik lalu tekan Enter:
   ```
   tcp.port == 5000
   ```
2. Untuk hanya melihat paket yang berisi data (bukan ACK kosong):
   ```
   tcp.port == 5000 && tcp.len > 0
   ```
3. Klik kanan salah satu paket → **Follow → TCP Stream** (atau `Ctrl+Alt+Shift+T`).
   - Pilih *Show data as* **ASCII**.
   - Teks **merah** = data dari klien (`--connect`) ke server; teks **biru** = data dari server (`--listen`) ke klien.
   - Sebelum setiap JSON akan terlihat 3–4 karakter aneh (misal `...a`). Itu adalah **prefix panjang 4 byte** dari protokol kita, bukan bagian dari ciphertext.

## 3. Mencari ciphertext tertentu (cocokkan dengan log terminal)

Setiap pesan di terminal punya nomor `seq`, misalnya:

```
[2026-10-01 19:54:54] [Alice] [SEND] seq=1 -> 127.0.0.1:63303
    plaintext  : Halo Bob, ini Alice
    iv         : 86157D74185FB268
    ciphertext : F48E4DE8F5DD7876169DE26AD8B390C6AB369B1716C64B62
```

1. Salin hex ciphertext dari log (cukup 16 karakter pertama pun bisa).
2. Di Wireshark: **Edit → Find Packet** (`Ctrl+F`).
3. Atur tiga dropdown di toolbar pencarian:
   - **Packet bytes** (bukan *Packet list*, karena di *Packet list* pencarian tidak menemukan isi payload),
   - **Narrow & Wide** (atau *Narrow (UTF-8 / ASCII)*),
   - **String**.
4. Tempel hex ciphertext lalu klik **Find**. Paket yang berisi JSON
   `{"seq":1,"iv":"86157D74185FB268","ciphertext":"F48E4DE8..."}` akan tersorot.
5. Bandingkan `seq`, `iv`, dan `ciphertext` di panel bytes dengan log pengirim dan penerima: ketiganya sama persis.

Program menulis hex dalam huruf **kapital** baik di log maupun di jaringan, jadi pencarian *case-sensitive* juga tetap cocok.

## 4. Skenario demo berurutan

Siapkan dua terminal (T1 = Alice, T2 = Bob) dan Wireshark dengan capture aktif.

### a. Mode `--plain`: plaintext terbaca

```bash
# T1
python peer.py --listen --name Alice --plain
# T2
python peer.py --connect 127.0.0.1 --name Bob --plain
```

Kedua terminal menampilkan banner merah **PERINGATAN: MODE --plain AKTIF**.
Dari Alice ketik `Halo Bob, ini Alice`. Di Follow TCP Stream terlihat jelas:

```
...+{"seq":1,"plaintext":"Halo Bob, ini Alice"}
```

Ketik `/quit` di salah satu terminal untuk menutup kedua peer.

### b. Mode DES: hanya IV dan ciphertext yang terlihat

Mulai capture baru (**Capture → Restart**, atau `Ctrl+R`), lalu:

```bash
# T1
python peer.py --listen --name Alice
# T2
python peer.py --connect 127.0.0.1 --name Bob
```

Kirim pesan yang **sama** (`Halo Bob, ini Alice`). Follow TCP Stream kini hanya menampilkan:

```
...a{"seq":1,"iv":"86157D74185FB268","ciphertext":"F48E4DE8F5DD7876169DE26AD8B390C6AB369B1716C64B62"}
```

Cari string `Halo` dengan Find Packet: **tidak ditemukan**.

### c. Pesan identik dikirim dua kali menghasilkan ciphertext berbeda

Dari Alice ketik `Pesan sama` dua kali. Contoh hasil:

```
seq=2  iv=6348BA5ADB29F145  ciphertext=54EB6C2091584151D773D238DC2DA4E6
seq=3  iv=72471C0DDBCA258E  ciphertext=01191B02E70CA61AD82BA4146D3B2A08
```

Plaintext sama, tetapi IV acak berbeda sehingga blok pertama CBC
`E_K(P_1 XOR IV)` berbeda, dan perbedaan itu merambat ke blok berikutnya.
Penyadap tidak bisa tahu bahwa dua pesan tersebut identik.

### d. Komunikasi dua arah

Ketik pesan dari Bob (T2), misalnya `Halo Alice 👋 apa kabar?`.
Di Follow TCP Stream terlihat payload dalam **dua warna** (merah dan biru), artinya
data mengalir dari kedua arah. Di panel paket, kolom *Source*/*Destination* port
bergantian antara `5000` dan port ephemeral klien.

### e. Bukti key tidak ditransmisikan

Key ada di `shared_key.txt` (contoh: `133457799BBCDFF1`).

1. **Edit → Find Packet**, pilih *Packet bytes* + *String*, cari `133457799BBCDFF1`.
   Hasilnya: status bar Wireshark menampilkan pesan bahwa **tidak ada paket yang cocok** (tidak ditemukan).
2. Ulangi dengan tipe **Hex value** dan nilai `13 34 57 79 9B BC DF F1` (key dalam bentuk byte mentah): juga **tidak ditemukan**.
3. Coba juga huruf kecil `133457799bbcdff1`: tidak ditemukan.

Ini membuktikan key adalah *pre-shared key* yang tidak pernah dikirim, baik sebagai teks maupun byte.

## 5. Alternatif: capture lewat terminal (tcpdump)

Linux / macOS / VM:

```bash
sudo tcpdump -i lo -w demo.pcap port 5000
# ... jalankan kedua peer dan kirim pesan ...
# tekan Ctrl+C untuk berhenti
```

Untuk dua komputer, ganti `-i lo` dengan interface jaringan (cek dengan `ip a`, misal `-i eth0` / `-i wlan0`).
Buka `demo.pcap` di Wireshark (**File → Open**) lalu lakukan langkah 2–4 seperti biasa.

Windows (opsional, lewat Wireshark CLI):

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D          # lihat daftar interface
& "C:\Program Files\Wireshark\tshark.exe" -i <nomor_loopback> -f "tcp port 5000" -w demo.pcap
```

## 6. Tips

- **Mulai capture sebelum peer terhubung**, agar handshake TCP terekam dan Follow TCP Stream lengkap.
- Jika memakai port lain (`--port 6000`), sesuaikan filter menjadi `tcp.port == 6000`.
- Di Windows tanpa Npcap Loopback, traffic `127.0.0.1` tidak bisa di-capture. Solusinya pasang ulang Npcap dengan opsi *Support loopback traffic*, atau jalankan peer memakai IP LAN laptop (misal `--connect 192.168.1.10`) lalu capture di interface Wi-Fi.
- Pakai opsi `--log alice.log` untuk menyimpan salinan output terminal sebagai lampiran laporan.
- Untuk screenshot, letakkan dua terminal berdampingan dengan Wireshark di bawahnya, lalu sorot `seq` yang sama di ketiganya.
