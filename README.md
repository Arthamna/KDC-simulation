# Simulasi KDC dan Chat AES melalui Tailscale

Panduan menjalankan **tiga perangkat dengan tiga IP berbeda** dalam satu jaringan privat Tailscale: satu sebagai **KDC**, satu sebagai **Alice**, dan satu sebagai **Bob**. Perangkat dapat menggunakan Wi-Fi atau koneksi internet yang berbeda selama tergabung dalam tailnet yang sama.

Program menggunakan Python standard library. AES-128, mode CBC, padding PKCS#7, dan alur distribusi key KDC diimplementasikan manual di repository ini. Tailscale menyediakan konektivitas antarperangkat; enkripsi pesan aplikasi tetap dilakukan oleh implementasi AES program.

## 1. Ketentuan tugas dan implementasi

| Ketentuan | Implementasi / persiapan demo |
| --- | --- |
| Individu atau kelompok maksimal 2 orang | Tetap siapkan 3 perangkat untuk peran KDC, Alice, dan Bob. |
| KDC, Alice, Bob menggunakan 3 IP berbeda | Gunakan IPv4 Tailscale masing-masing perangkat, seperti tabel di bawah. |
| Distribusi key 5 langkah, lalu komunikasi AES | Alice meminta session key ke KDC, meneruskan ticket ke Bob, lalu menyelesaikan challenge-response. |
| Alice dan Bob dapat menjadi sender dan receiver | Satu koneksi TCP Alice–Bob dipakai untuk chat dua arah setelah autentikasi berhasil. |
| AES dan KDC manual | Lihat `crypto/` untuk AES/CBC/padding, serta `kdc/` dan `network/` untuk protokol KDC. Tidak memerlukan PyCryptodome atau library kriptografi eksternal. |
| Key dan plaintext ASCII; ciphertext Hex | Master key dan session key tepat 16 karakter ASCII. Pesan harus ASCII; log TX/RX menampilkan IV dan ciphertext dalam Hex. |
| Key dapat diubah, program interaktif | Master key diinput saat startup dan dapat diganti melalui menu tanpa restart. Alice dapat meminta session key baru melalui menu rekey. |
| Wireshark siap sebelum demo | Mulai capture di perangkat Alice sebelum handshake agar pertukaran KDC dan chat terlihat. Lihat bagian 8. |

Alur lima langkah pada bagian 6 menjelaskan **implementasi repository ini**. Cocokkan kembali susunan field/pesan dengan PPT kelas; PPT tidak disertakan dalam repository.

## 2. Topologi dan pembagian IP

Contoh alamat yang dipakai dalam panduan:

| Perangkat | Peran | Contoh IPv4 Tailscale | Port aplikasi |
| --- | --- | --- | --- |
| Device 1 | KDC | `100.101.102.10` | Listen TCP `9000` |
| Device 2 | Alice | `100.101.102.11` | Port sumber TCP otomatis; tidak membuka listener |
| Device 3 | Bob | `100.101.102.12` | Listen TCP `9001` |


**Semua IP di atas adalah contoh**

`--host` selalu merupakan **IP milik perangkat yang sedang menjalankan perintah**. Khusus Alice, IP ini juga dipakai untuk bind alamat sumber koneksi ke KDC dan Bob. Karena transport menggunakan IPv4, gunakan hasil `tailscale ip -4`.

## 3. Persiapan pada ketiga perangkat

1. Siapkan komputer Windows, Linux, atau macOS yang dapat menjalankan Python **3.9 atau lebih baru**.
2. Install [Python](https://www.python.org/downloads/) dan [Tailscale](https://tailscale.com/download) pada ketiganya. Di Windows, aktifkan opsi Python untuk ditambahkan ke `PATH`.
3. Install [Wireshark](https://www.wireshark.org/download.html) setidaknya di perangkat Alice. Di Windows, sertakan Npcap dari installer untuk capture interface lokal.
4. Salin versi repository yang sama ke setiap perangkat. Jika menggunakan Git, jalankan:

   ```powershell
   git clone https://github.com/Arthamna/KDC-simulation.git
   ```

5. Buka terminal **di folder `KDC-simulation`**, yaitu folder yang berisi `README.md`, `crypto/`, `kdc/`, `network/`, dan `tests/`. Semua perintah `python -m ...` di panduan ini dijalankan dari folder tersebut.
6. Periksa Python:

   ```powershell
   python --version
   ```

   Di Windows, jika tersedia sebagai `py`, gunakan `py -3` sebagai pengganti `python`. Di Linux/macOS, gunakan `python3` bila diperlukan. Tidak ada dependency Python tambahan yang perlu di-install melalui `pip`.

## 4. Setup Tailscale: satukan ketiga perangkat dalam satu tailnet

### 4.1 Login dan daftarkan perangkat

1. Di Device 1, buka Tailscale dan login untuk membuat/memilih tailnet.
2. Di Device 2 dan Device 3, login ke **tailnet yang sama**. Untuk perangkat milik sendiri, gunakan akun Tailscale yang sama. Untuk anggota kelompok dengan akun berbeda, undang melalui halaman **Users** di [admin console](https://login.tailscale.com/admin), terima undangannya, lalu pilih tailnet kelompok saat login.
3. Periksa halaman **Machines** di admin console: ketiga perangkat harus terdaftar dan online. Jika tailnet mewajibkan persetujuan perangkat, selesaikan persetujuannya.
4. Agar mudah dikenali, beri nama perangkat `kdc`, `alice`, dan `bob` melalui admin console.
5. Pada setiap perangkat, jalankan:

   ```powershell
   tailscale status
   tailscale ip -4
   ```

   Catat hasil IPv4 masing-masing dan gunakan sebagai pengganti IP contoh pada bagian 2. Jika CLI belum ditemukan di Windows, buka ulang terminal atau gunakan executable berikut, misalnya:

   ```powershell
   & "C:\Program Files\Tailscale\tailscale.exe" ip -4
   ```

Koneksi ini cukup menggunakan jaringan privat Tailscale antarperangkat. Tidak perlu menambahkan subnet router, exit node, port forwarding router, atau Tailscale Funnel untuk skenario ini.

### 4.2 Periksa koneksi antarperangkat

Dari Alice, cek KDC dan Bob:

```powershell
tailscale ping 100.101.102.10
tailscale ping 100.101.102.12
```

Dari KDC dan Bob, cek Alice:

```powershell
tailscale ping 100.101.102.11
```

### 4.3 Izinkan koneksi aplikasi

- Pastikan pengaturan Tailscale KDC dan Bob mengizinkan koneksi masuk; nonaktifkan **Shields up / Block incoming connections** jika aktif.
- Jika tailnet menggunakan access policy khusus, izinkan **Alice → KDC TCP 9000** dan **Alice → Bob TCP 9001**, termasuk trafik balasannya. Bob mengirim chat balik melalui koneksi TCP yang sama; Alice tidak memerlukan listener tambahan.
- Pastikan firewall sistem mengizinkan kedua listener tersebut.

Untuk Windows, bila diperlukan, jalankan PowerShell **sebagai Administrator** dengan IP aktual. 

Di **KDC**:

```powershell
New-NetFirewallRule -DisplayName "KDC demo TCP 9000" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9000 -RemoteAddress 100.101.102.11 -Profile Any
```

Di **Bob**:

```powershell
New-NetFirewallRule -DisplayName "Bob demo TCP 9001" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9001 -RemoteAddress 100.101.102.11 -Profile Any
```

Di Linux dengan UFW aktif, aturan setaranya adalah `sudo ufw allow from 100.101.102.11 to any port 9000 proto tcp` di KDC dan `sudo ufw allow from 100.101.102.11 to any port 9001 proto tcp` di Bob. Di macOS, izinkan koneksi masuk untuk Python jika diminta firewall.

## 5. Jalankan program berdasarkan perangkat

Gunakan satu terminal program di setiap perangkat. Urutan yang disarankan: **KDC → Bob → Alice**. Siapkan capture Wireshark pada bagian 8 **sebelum Alice memilih Start/Rekey session**.

### 5.1 Tentukan master key

Program meminta master key melalui input, bukan melalui argumen CLI atau perubahan source code. Contoh **key dummy untuk demo**, masing-masing tepat 16 karakter ASCII:

| Key | Nilai contoh | Diinput pada |
| --- | --- | --- |
| `Ka` | `AliceMasterKey01` | KDC pada prompt Alice, dan perangkat Alice |
| `Kb` | `BobMasterKey0001` | KDC pada prompt Bob, dan perangkat Bob |

`Ka` di Alice harus persis sama dengan `Ka` di KDC; `Kb` di Bob harus persis sama dengan `Kb` di KDC. Huruf besar/kecil dan spasi dihitung. Masukkan nilainya tanpa tanda kutip. Master key disepakati sebelum demo; session key `Ks` dibuat otomatis oleh KDC untuk setiap permintaan sesi baru.

### 5.2 Device 1 — KDC (`100.101.102.10`)

```powershell
python -m kdc.server --host 100.101.102.10 --port 9000
```

Isi prompt:

```text
Alice master key (16 ASCII chars): AliceMasterKey01
Bob master key (16 ASCII chars): BobMasterKey0001
```

Pastikan muncul `[KDC] Listening on 100.101.102.10:9000`. Biarkan program berjalan. Menu KDC: `1` mengganti key Alice, `2` mengganti key Bob, `0` keluar.

### 5.3 Device 3 — Bob (`100.101.102.12`)

```powershell
python -m network.bob --host 100.101.102.12 --port 9001
```

Masukkan `BobMasterKey0001` pada prompt master key. Pastikan muncul `[Bob] Listening on 100.101.102.12:9001`, lalu biarkan program menunggu Alice.

| Menu Bob | Fungsi |
| --- | --- |
| `1` | Ganti master key Bob; sinkronkan nilainya di KDC. |
| `2` | Kirim chat setelah sesi terautentikasi. |
| `3` | Akhiri sesi chat. Listener tetap berjalan. |
| `4` | Periksa status; sesi siap ditandai `Authenticated`. |
| `0` | Keluar. |

### 5.4 Device 2 — Alice (`100.101.102.11`)

Opsional, di terminal PowerShell terpisah pada Alice, periksa listener yang sudah berjalan:

```powershell
Test-NetConnection 100.101.102.10 -Port 9000
Test-NetConnection 100.101.102.12 -Port 9001
```

Keduanya harus menunjukkan `TcpTestSucceeded : True`. Probe ini membuka lalu menutup koneksi tanpa pesan protokol; log `Connection closed` dapat muncul di server saat pemeriksaan. Lakukan pemeriksaan ini sebelum capture demo dimulai.

Jalankan Alice:

```powershell
python -m network.alice --host 100.101.102.11 --kdc-host 100.101.102.10 --kdc-port 9000 --bob-host 100.101.102.12 --bob-port 9001
```

Masukkan `AliceMasterKey01` pada prompt master key.

| Menu Alice | Fungsi |
| --- | --- |
| `1` | Ganti master key Alice; sinkronkan nilainya di KDC. |
| `2` | Ganti IP tujuan KDC/Bob. Port tetap mengikuti argumen startup. |
| `3` | Start/Rekey session: jalankan distribusi key dan autentikasi. |
| `4` | Kirim chat setelah sesi terautentikasi. |
| `5` | Akhiri sesi chat. |
| `0` | Keluar. |

Setelah capture aktif, pilih **`3`**. Keberhasilan ditandai:

```text
[Alice] Steps 1-2 completed: session key received
[Alice] Steps 3-5 completed: authenticated session ready
```

Pada Bob muncul `[Bob] Authentication successful from 100.101.102.11`. Setelah itu kedua pihak dapat mengirim pesan tanpa handshake ulang untuk setiap pesan.


## 6. Uji chat dua arah dan penggantian key

### 6.1 Alice sebagai sender, Bob sebagai receiver

1. Pada Alice, pilih menu **`4`**.
2. Masukkan pesan ASCII, misalnya `Halo Bob, pesan dari Alice 123!`.
3. Alice menampilkan `[Alice TX] IV=... CIPHER=...`.
4. Bob menampilkan `[Bob RX] IV=... CIPHER=...` dan plaintext `[Alice] Halo Bob, pesan dari Alice 123!`.

### 6.2 Bob sebagai sender, Alice sebagai receiver

1. Pada Bob, pilih menu **`2`**.
2. Masukkan `Halo Alice, pesan diterima oleh Bob.`.
3. Bob menampilkan log `[Bob TX]`; Alice menampilkan `[Alice RX]` serta plaintext `[Bob] ...`.

Kedua pihak dapat mengirim beberapa pesan selama sesi aktif. Pesan tidak harus 16 karakter; padding dan CBC menangani pesan multiblok. Gunakan karakter ASCII seperti huruf Latin tanpa aksen, angka, spasi, dan tanda baca. Emoji dan karakter non-ASCII akan ditolak. IV dan ciphertext tampil sebagai karakter Hex `0-9` dan `a-f`; IV 16 byte ditampilkan sebagai 32 karakter Hex.

### 6.3 Ganti master key tanpa restart

Contoh mengganti kedua master key:

1. Pada Alice, pilih **`5`** untuk mengakhiri sesi aktif.
2. Pada KDC, pilih **`1`**, masukkan `NewAliceMaster01`.
3. Pada Alice, pilih **`1`**, masukkan `NewAliceMaster01` yang sama.
4. Pada KDC, pilih **`2`**, masukkan `NewBobMaster0001`.
5. Pada Bob, pilih **`1`**, masukkan `NewBobMaster0001` yang sama.
6. Pada Alice, pilih **`3`** untuk handshake baru, kemudian uji kirim pesan dari kedua arah.

Kedua key pengganti di atas juga tepat 16 karakter ASCII. Pergantian master key pada Alice/Bob menutup sesi lokal yang aktif. Mengubah key di KDC saja tidak mengganti session key sesi chat yang sudah berjalan; sinkronkan key pada entitas terkait lalu mulai sesi baru.

Untuk hanya **mengganti session key**, pilih menu **`3`** pada Alice ketika master key tetap sinkron. Sesi sebelumnya ditutup dan KDC menghasilkan `Ks` baru secara otomatis. Tidak ada menu input `Ks` manual.