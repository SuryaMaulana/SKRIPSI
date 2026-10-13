# Panduan anotasi audit manusia

Panduan ini untuk dua anotator (anotator 1 dan anotator 2). Anotator tidak perlu membaca kode.
Lembar **Panduan** di dalam berkas xlsx dibuat lebih dulu. Bila keduanya berbeda, yang berlaku adalah panduan ini
(lihat bagian 6).

## 1. Berkas dan urutan kerja

| Anotator | Fase A: label kelas (100 baris) | Fase B: relevansi bukti (277 butir) |
|---|---|---|
| 1 | `anotasi_A_anotator1.xlsx` | `anotasi_B_anotator1.xlsx` |
| 2 | `anotasi_A_anotator2.xlsx` | `anotasi_B_anotator2.xlsx` |

- Setiap anotator hanya menerima dua berkasnya dan panduan ini, tanpa akses ke repositori.
- Kedua anotator mendapat 100 baris log yang sama dalam urutan acak yang berbeda. Isi hanya lembar **Anotasi**.
- Kerjakan **Fase A sampai selesai dan simpan, baru buka Fase B.** Fase B menampilkan prediksi model untuk baris yang
  sama, jadi melihatnya lebih dulu akan memengaruhi label Fase A. Setelah membuka Fase B, jangan mengubah Fase A lagi.
- Kerjakan sendiri. Jangan berdiskusi dengan anotator lain sampai keempat berkas diserahkan.
- Berkas yang sudah diserahkan tidak diubah lagi; kappa dihitung dari berkas itu. Diskusi sesudahnya hanya memakai
  daftar baris "perlu diskusi" (berisi id dan label kedua anotator, tanpa label dataset), dan hasil diskusi dicatat
  terpisah. Rincian per baris hasil perhitungan (di `results/`) memuat label dataset dan tidak dibagikan ke anotator.

## 2. Aturan umum untuk Fase A dan Fase B

### Yang boleh dan tidak boleh dipakai

- **Boleh:**
  - kolom `path_norm`, `query_norm`, `ua_norm` (Fase A);
  - URL-decoder yang berjalan lokal, misalnya CyberChef di peramban (operasi *URL Decode*, ulangi sampai tidak
    berubah), atau Python: jalankan
    `python3 -c 'import sys,urllib.parse as u; s=sys.stdin.read().strip(); [print(s:=u.unquote_plus(s)) for _ in range(3)]'`,
    tempel teksnya, lalu tekan Ctrl-D;
  - dokumentasi umum untuk arti istilah, misalnya nama metode HTTP;
  - fitur pencarian (Ctrl+F) untuk memeriksa item yang panjang.
- **Tidak boleh**, sampai keempat berkas diserahkan:
  - ChatGPT atau LLM lain, maupun alat klasifikasi otomatis;
  - folder `results/`, `reports/`, atau `data/` di repositori, baik lokal maupun di GitHub. Isinya menunjukkan label
    dataset dan metode asal setiap butir;
  - berkas kunci (`audit_B_key.json`, `audit_100_ids.json`);
  - berkas anotator lain.

### Membaca baris log

- `raw_log_masked` adalah baris log akses. Waktunya disamarkan menjadi `01/Jan/2020:00:00:00` dan versi protokolnya
  menjadi `HTTP/1.1`. Alamat IP `172.26.0.1` sama untuk semua baris di dataset.
- Urutan bagiannya: IP, waktu, `"metode path?query protokol"`, kode status, ukuran, `"Referer"`, `"User-Agent"`.
- Di `raw_log_masked`, tanda kutip di dalam Referer atau User-Agent ditulis `\"`, dan byte khusus ditulis `\xhh`.
  Bacalah `\"` sebagai `"`.

### Decode

Payload sering ter-encode. Untuk membaca dan mencocokkan, decode berulang (paling banyak 3 kali) sampai teks tidak
berubah:

- `%xx` diubah menjadi karakter aslinya, misalnya `%27` menjadi `'`, `%2F` menjadi `/`, `%2527` menjadi `%27` lalu `'`;
- `+` boleh dibaca sebagai spasi;
- entity HTML diubah, misalnya `&lt;` menjadi `<`.

## 3. Fase A: label kelas

### Kolom

| Kolom | Isi | Diubah? |
|---|---|---|
| `no` | nomor baris | jangan |
| `id` | id baris (acak, tidak bermakna) | jangan |
| `raw_log_masked` | baris log akses | jangan |
| `path_norm`, `query_norm`, `ua_norm` | path, query string, dan User-Agent setelah decode sampai 3 lapis dan entity HTML. Di query, `+` menjadi spasi; di path dan User-Agent, `+` tetap `+`. Escape `\"` dibaca menjadi `"`, dan karakter kontrol ditulis `\xhh`. Sejumlah kata kunci (SQL, HTML/JavaScript, perintah shell, skema URL) ditulis huruf kecil, dan angka panjang/UUID ditulis `<*>` | jangan |
| `label_anotator` | **wajib**: satu label dari dropdown | isi |
| `catatan` | opsional: alasan atau tanda ragu | isi |

Referer tidak punya kolom hasil decode. Referer ada di `raw_log_masked`.

### Label yang sah

Ada tepat enam label: `SQLI`, `XSS`, `PATH_TRAVERSAL`, `CMD_INJECTION`, `WEB_SCANNING`, `NORMAL`. Pilih dari
dropdown. Skrip mengabaikan spasi dan huruf besar/kecil (`normal` diterima). Singkatan dan ejaan lain ditolak, misalnya
`PT`, `CMD`, `PATH TRAVERSAL`, atau `Path-Traversal`.

### Definisi kelas (ringkasan Tabel 1 naskah dan Tabel 2.1 skripsi)

Kolom indikator berisi **contoh**, bukan daftar lengkap; yang menentukan adalah definisi kelas. Indikator bisa berada di
metode, path, query string, User-Agent, atau Referer, tidak hanya di parameter.

| Label | Definisi | Contoh indikator |
|---|---|---|
| `SQLI` | sintaks SQL disisipkan untuk memanipulasi kueri basis data | `' OR 1=1`, `' AND '1'='2`, `UNION SELECT`, `SLEEP(`, komentar `--` atau `#`; sering ter-encode (`%27`, `%20`) |
| `XSS` | skrip sisi klien disisipkan agar dijalankan di peramban korban | `<script>`, `onerror=`, `javascript:`, varian ter-encode (`%3Cscript%3E`); bisa muncul di Referer |
| `PATH_TRAVERSAL` | akses berkas di luar web root, atau penyertaan berkas lokal/jarak jauh | `../`, `..%2f`, `/etc/passwd`, `win.ini`; URL eksternal ber-skema (`http://...`) di path atau parameter (RFI) |
| `CMD_INJECTION` | perintah sistem operasi disisipkan lewat permintaan | pemisah perintah shell (`;`, `&`, `&&`, `\|`, `\|\|`, baris baru) diikuti perintah seperti `id`, `cat /etc/passwd`, `sleep 15`; backtick atau `$(...)`; varian ter-encode (`%7C`, `%26%26`, `%60`); Shellshock `() {`; argumen PHP-CGI `-d allow_url_include` |
| `WEB_SCANNING` | pemindaian otomatis untuk menemukan berkas, direktori, atau kemampuan server | User-Agent pemindai (Nmap, zgrab, sqlmap); metode non-standar (definisi D1); permintaan tanpa payload ke berkas sensitif (definisi D2); probe `/wp-login.php` |
| `NORMAL` | permintaan sah pengguna atau crawler mesin pencari | URI wajar, parameter alfanumerik, status 200/301/304, User-Agent peramban atau bot mesin pencari yang dikenal dari namanya (mis. Googlebot, bingbot) |

Batasan:

- **URL eksternal** adalah URL ke host selain situs uji `test-site.com`. URL ke `test-site.com` (misalnya di Referer
  atau di parameter `url=`) bukan indikator. URL di Referer atau User-Agent juga bukan indikator RFI.

Definisi eksplisit (keputusan penulis):

- **D1.** metode selain GET, HEAD, POST, OPTIONS dihitung indikator WEB_SCANNING (mis. PROPFIND, MKCOL, TRACK, PUT, PATCH)
- **D2.** permintaan tanpa payload ke berkas sensitif dihitung WEB_SCANNING: cadangan (.bak, .backup, .old, .swp, ~), log (.log), konfigurasi (.htaccess, /.env), VCS (.git/, .svn/)

### Cara memutuskan

1. Nilai hanya apa yang terlihat di baris itu. Setiap baris dinilai sendiri.
   - Indikator yang butuh beberapa baris (mis. kode 404 beruntun) tidak dipakai.
   - Kode status sendirian, misalnya 404, bukan indikator serangan.
2. Cari indikator di metode, path, query string, User-Agent, dan Referer.
3. Jika tidak ada indikator serangan, pilih `NORMAL`. Jika ragu apakah sesuatu termasuk indikator serangan, pilih
   `NORMAL`.
4. Jika ada indikator satu kelas saja, pilih kelas itu.
5. Jika ada indikator lebih dari satu kelas, pilih menurut prioritas berikut (sama dengan prioritas pelabelan di naskah
   dan skripsi): **`CMD_INJECTION` > `SQLI` > `XSS` > `PATH_TRAVERSAL` > `WEB_SCANNING`**. Contohnya,
   `&&cat /etc/passwd` memuat indikator `CMD_INJECTION` dan `PATH_TRAVERSAL`, jadi labelnya `CMD_INJECTION`.

### Menandai baris yang ragu

Tidak ada kolom khusus untuk ini. Tetap pilih satu label menurut langkah 3–5, karena sel kosong ditolak. Lalu tulis di
`catatan` dengan awalan `RAGU:` dan alasannya. Contohnya, label `NORMAL` dengan catatan
`RAGU: SQLI atau NORMAL, hanya ada tanda kutip`. Catatan tidak dihitung skrip; catatan dipakai saat diskusi.

### Contoh terisi

Tiga baris nyata dari split validasi SR-BH 2020. Baris-baris ini bukan bagian dari 100 baris audit maupun 500 baris
sampel uji, dan permintaannya (metode, path, query) tidak muncul di sampel uji.

**A-1** `srbh-44869ede21c898f8`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL--+-/03/22/quidem-rerum-sit-doloribus-quia-eum HTTP/1.1" 404 53918 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

- `path_norm`: `/blog/index.php/2020')+union+all+select+null,null,null--+-/03/22/quidem-rerum-sit-doloribus-quia-eum`
- `label_anotator`: **`SQLI`**
- `catatan`: `UNION ALL SELECT dan komentar -- di path`

**A-2** `srbh-b18ebdca6394eb6b`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-content/plugins/user-registration/assets/js/jquery-tiptip/jquery.tipTip.min.js?ver=1.3.0%26%26cat+%2Fetc%2Fpasswd HTTP/1.1" 200 2744 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

- `query_norm`: `ver=1.3.0&&cat /etc/passwd`
- `label_anotator`: **`CMD_INJECTION`**
- `catatan`: `&&cat (CMD) dan /etc/passwd (PT); prioritas -> CMD`

**A-3** `srbh-9bc8037170253574`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/04/04/explicabo-qui-fuga-distinctio-dolores-voluptatibus-sit/ HTTP/1.1" 200 21063 "-" "Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0"
```

- `label_anotator`: **`NORMAL`**
- `catatan`: kosong

## 4. Fase B: relevansi bukti

Setiap baris adalah satu **butir**: satu item evidence yang ditulis sebuah metode untuk mendukung prediksinya
(`label_prediksi`) pada satu baris log. Item yang ditulis persis sama oleh kedua metode untuk prediksi yang sama
digabung menjadi satu butir. Satu baris log bisa muncul di beberapa butir, dengan item atau `label_prediksi` yang
berbeda. Setiap butir dinilai terhadap `label_prediksi` miliknya sendiri.

### Kolom

| Kolom | Isi | Diubah? |
|---|---|---|
| `no` | nomor butir; dipakai skrip untuk mencocokkan butir dengan kunci | jangan |
| `id`, `raw_log_masked` | baris log | jangan |
| `label_prediksi` | kelas yang diprediksi metode | jangan |
| `evidence_item` | item yang dinilai; `[item kosong]` berarti metode menulis item tanpa isi | jangan |
| `skor` | **wajib**: `0`, `1`, atau `2` dari dropdown | isi |
| `catatan` | opsional | isi |

### Metode disamarkan

Anotator tidak tahu metode mana yang menulis sebuah butir:

- tidak ada kolom metode;
- urutan butir diacak berbeda untuk tiap anotator;
- item yang identik di kedua metode digabung;
- berkas hanya berisi lembar Anotasi dan Panduan, tanpa kolom atau baris tersembunyi.

Pemetaan butir ke metode disimpan di berkas kunci terpisah yang tidak dibagikan. Jangan mencoba menebak metode.

### Skala skor

Nilai setiap butir dalam dua langkah.

1. **Apakah item ada di baris log?**
   - Item ada bila isinya muncul utuh dan berurutan di baris log, apa adanya atau setelah decode (bagian 2).
   - Item juga boleh di-decode dengan cara yang sama sebelum dicocokkan.
   - Spasi dan tanda kutip di awal/akhir item, serta perbedaan huruf besar/kecil, diabaikan.
   - **D3.** untuk butir berpola `<nama>: <nilai>`, hanya nilainya yang dicocokkan ke log; nama bagian diabaikan
   - Item **tidak ada** bila berupa uraian, parafrase, gabungan potongan yang tidak bersambung, atau teks yang tidak
     muncul di baris. Contohnya, `UNION SELECT` tidak ada di baris yang berisi `UNION ALL SELECT`.
   - Untuk item panjang, cek dengan Ctrl+F. Jumlah pengulangan (mis. `..%2F`) harus cocok: item boleh lebih pendek dari
     bagian log, tetapi tidak boleh lebih panjang.
2. **Apakah item menunjukkan `label_prediksi`?** Item menunjukkan kelas itu bila memuat indikatornya menurut tabel
   definisi di bagian 3.

| Skor | Definisi operasional |
|---|---|
| `2` | Item ada di baris log (langkah 1) dan memuat indikator `label_prediksi` (langkah 2). |
| `1` | Item ada di baris log, tetapi tidak memuat indikator `label_prediksi`. Contohnya bagian umum seperti metode `GET`, path biasa, kode status, atau User-Agent peramban pada prediksi serangan, atau indikator kelas lain. Item yang ada di baris log tidak pernah diberi 0. |
| `0` | Item tidak ada di baris log (uraian, parafrase, atau teks rekaan), atau `[item kosong]`. |

Ketentuan tambahan:

- **Nilai terhadap `label_prediksi`, bukan terhadap label yang menurut Anda benar.** Prediksi yang salah tetap bisa
  mendapat 2 bila itemnya memuat indikator kelas yang diprediksi. Aturan prioritas Fase A tidak dipakai di Fase B.
- **Bila `label_prediksi` adalah `NORMAL`:**
  - skor 2 bila item ada, menunjukkan ciri permintaan wajar menurut tabel definisi (URI biasa, parameter alfanumerik,
    status 200/301/304, User-Agent peramban atau bot mesin pencari), dan tidak memuat indikator serangan;
  - skor 1 bila item ada tetapi memuat indikator serangan (mis. `../`, `<script>`, URL eksternal ber-skema di path atau
    parameter), atau hanya berupa bagian umum seperti `GET`.
- **`[item kosong]` selalu diberi 0.**
- **Ragu antara dua skor:** pilih skor yang lebih rendah, lalu tulis `RAGU:` dan alasannya di `catatan`.

### Contoh terisi

Ketiga contoh adalah keluaran model nyata pada baris split validasi. Contoh ini bukan butir audit, dan metode asalnya
tidak disebutkan.

**B-1** `srbh-2b5e984e87acdfa2`, `label_prediksi` = `SQLI`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/04/04/explicabo-qui-fuga-distinctio-dolores-voluptatibus-sit/feed%27+AND+%271%27%3D%272 HTTP/1.1" 404 53918 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

- `evidence_item`: `feed%27+AND+%271%27%3D%272`
- `skor`: **`2`**
- Alasannya: item ada apa adanya, dan setelah decode menjadi `feed' AND '1'='2`, yaitu perbandingan boolean SQL setelah
  tanda kutip (indikator SQLI).

**B-2** `srbh-8e256d45987c63ac`, `label_prediksi` = `NORMAL`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/tag/https%3A%2F%2Fwww.google.com%2F HTTP/1.1" 404 276 "http://test-site.com/blog/index.php/tag/hic-quod-et-odit/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

- `evidence_item`: `GET /blog/index.php/tag/https%3A%2F%2Fwww.google.com%2F HTTP/1.1`
- `skor`: **`1`**
- Alasannya: item ada, tetapi memuat URL eksternal ber-skema `https://www.google.com/` di path. Itu indikator
  `PATH_TRAVERSAL` (RFI), bukan ciri permintaan wajar.

**B-3** `srbh-c126bde1821eddb4`, `label_prediksi` = `NORMAL`

```
172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/04/04/inventore-asperiores-adipisci-cum-facere-voluptatem-rerum/ HTTP/1.1" 200 21906 "-" "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4"
```

- `evidence_item`: `Permintaan sah pengguna atau crawler mesin pencari`
- `skor`: **`0`**
- Alasannya: item ini uraian, tidak ada di baris log.

## 5. Aturan kerja, penyimpanan, dan pemeriksaan skrip

- Isi hanya `label_anotator` (Fase A) atau `skor` (Fase B), ditambah `catatan` bila perlu.
- Jangan mengubah:
  - urutan baris (jangan memakai Sort atau Filter);
  - `no` atau `id`;
  - isi kolom lain, nama kolom, atau nama lembar `Anotasi`.
- Jangan menambah atau menghapus baris maupun kolom, dan jangan menulis apa pun di luar tabel.
- Pilih nilai dari dropdown, atau ketik persis sama. Jangan menempel nilai dari luar, karena tempelan bisa melewati
  validasi dropdown.
- Abaikan peringatan Excel seperti segitiga hijau "number stored as text". Jangan mengonversi isi sel.
- Pakai Microsoft Excel atau LibreOffice Calc. Hindari Google Sheets, karena konversi bolak-balik bisa mengubah teks
  payload.
- Simpan dengan **File > Save** sebagai `.xlsx` dengan **nama berkas yang sama**. Jangan simpan sebagai `.csv`, `.xls`,
  atau `.ods`.

### Saat penulis menjalankan perhitungan

Perintahnya `python -m src.eval.anotasi hitung --a1 ... --a2 ... --b1 ... --b2 ...`, dan keempat berkas wajib ada.

Yang diperiksa skrip:

- **Fase A:** dicocokkan menurut `id`. Diperiksa bahwa setiap `id` muncul tepat sekali dan setiap label sah.
- **Fase B:** dicocokkan menurut `no`. Diperiksa bahwa `id`, `label_prediksi`, dan `evidence_item` cocok dengan kunci,
  setiap butir muncul tepat sekali, dan setiap skor sah.
- Kolom lain, termasuk `raw_log_masked` dan `*_norm`, **tidak diperiksa**. Perubahan di kolom itu, atau pengurutan satu
  kolom saja, bisa lolos tanpa terdeteksi. Karena itu jangan diubah.

Bila ada masalah, **tidak ada sel yang dilewati: perhitungan ditolak seluruhnya**.

- Pesan galat menyebut nomor barisnya, misalnya `no 37 (...): label kosong/tidak sah None`,
  `no 12: isi baris tidak cocok dengan kunci`, atau `no 5: skor kosong/tidak sah '3'`.
- Berkas diperbaiki, lalu perhitungan dijalankan ulang.
- Saat meneruskan galat ke anotator, sebutkan nomor `no` saja. Kode butir seperti `B0007` jangan diteruskan, karena
  urutannya mengikuti pengelompokan kelas.
- Hanya baris yang semua selnya kosong yang diabaikan. Karena itu, baris data yang terhapus isinya akan terdeteksi
  sebagai id atau butir yang hilang.
- Label dibaca tanpa spasi dan tanpa membedakan huruf besar/kecil. Skor diterima sebagai angka atau teks `0`, `1`, `2`
  (`2.0` juga diterima). Isi `catatan` tidak dipakai dalam perhitungan.

## 6. Perbedaan dengan lembar Panduan di dalam xlsx

- **Pengurutan.** Lembar Panduan menulis "mengurutkan ulang baris boleh". Panduan ini melarang Sort dan Filter, karena
  pengurutan satu kolom saja bisa memindahkan label atau skor ke baris lain tanpa terdeteksi.
- **Aturan 3 Fase A.** Lembar Panduan berbunyi "bila ragu antara dua kelas serangan, pilih yang payload-nya paling
  eksplisit". Panduan ini menggantinya dengan prioritas `CMD_INJECTION` > `SQLI` > `XSS` > `PATH_TRAVERSAL` >
  `WEB_SCANNING` bila ada indikator lebih dari satu kelas.
- **Skor 0.** Lembar Panduan menulis "0: Tidak ada di baris log, atau tidak relevan". Menurut panduan ini, item yang ada
  di baris log tetapi tidak relevan diberi **1**, bukan 0. Skor 0 hanya untuk item yang tidak ada di baris log dan
  `[item kosong]`.
- **Urutan fase.** Lembar Panduan menulis "sampai kedua berkas selesai". Panduan ini memperjelas: Fase A diselesaikan
  dulu sebelum Fase B dibuka, dan larangan di bagian 2 berlaku untuk kedua fase.
- **Tambahan.** Panduan ini menambahkan definisi eksplisit D1–D3 (keputusan penulis), batasan definisi kelas (contoh
  tidak lengkap, URL eksternal), definisi "ada" (decode, tanda kutip, huruf besar/kecil), ketentuan untuk prediksi
  `NORMAL`, `[item kosong]`, dan ragu, serta contoh dari data nyata. Lembar Panduan Fase B hanya berisi contoh rekaan.
- Tabel definisi di lembar Panduan adalah Tabel 1 naskah dalam bahasa Inggris. Isinya sama dengan ringkasan di bagian 3,
  di luar batasan yang ditambahkan panduan ini.
