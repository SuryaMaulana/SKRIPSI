# Catatan Pembanding Regex (langkah B)

Catatan ini melengkapi `configs/regex_baseline.yaml` dan `configs/regex_full.yaml`. Isinya: kronologi varian
sekunder, keputusan di srbh_val, cakupan verifikasi, dan satu temuan yang menunggu keputusan penulis. Konfigurasi
yang sudah dijalankan pada data uji tidak diubah, agar `config_sha256` di rekaman run tetap cocok.

## 1. Pembanding utama (pra-registrasi)

- Konfigurasi: OWASP CRS 4.30.0, PL1, kategori 913/930/931/932/941/942 (71 aturan), ditambah aturan pemindaian
  Baş Seyyar dkk. Mesin acuan: ModSecurity 2.9.15 di Apache 2.4 (`configs/regex_baseline.yaml`, blok `engine`).
- Run resmi: `regex-20261007T150817Z-497dc3d` → `results/regex.jsonl`. Isinya tidak berubah oleh semua perubahan
  kode sesudahnya (diperiksa ulang baris per baris di setiap perubahan mesin).

## 2. Varian sekunder regex_full (post hoc)

Kronologi (commit di cabang `tahap-sistem`):

| langkah | commit / run |
|---|---|
| Pemetaan ditulis dan di-commit sebelum varian dijalankan | `5046290` |
| Kode pendukung (semua kategori, nilai bawaan 901, `--split`) | `da9dace` |
| Run val pertama: 920440 tidak pernah cocok karena aksi `setvar` belum diemulasi | (ditimpa run berikutnya) |
| Perbaikan emulasi `setvar` (bukan perubahan pemetaan) | `dd93c9b` |
| Run val resmi | `regex_full-20261007T152855Z-dd93c9b` → `results/tuning/regex_full_val.jsonl` |
| Keputusan val dicatat (tanpa penyesuaian pemetaan) | `675337d` |
| Satu kali run pada test_sample_500 (`post_hoc: true`) | `regex_full-20261007T153015Z-675337d` → `results/regex_full.jsonl` |

Bukti val untuk aturan kategori baru:
- **911100 → WEB_SCANNING:** 732 prediksi benar, 0 salah.
- **920440 → WEB_SCANNING:** 320 benar, 16 salah. Kesalahannya PATH_TRAVERSAL → WEB_SCANNING: probe RFI di path berakhiran `www.google.com`, dan `.com` termasuk `tx.restricted_extensions`.
- **933120/933140 → CMD_INJECTION:** masing-masing 64 benar, 0 salah.

Sebanyak 878 prediksi benar di val hanya didukung aturan kategori baru.

### Temuan setelah run uji (menunggu keputusan penulis)

Review sesudah run uji menemukan hal yang terlewat saat pengujian di val. Aturan **CRS 920500** (PL1, "Attempt to
access a backup or working file", pola `\.[^.~]+~(?:/.*|)$`) cocok pada 36 dari 38 baris WEB_SCANNING yang masih
lolos di val, tanpa satu pun hit pada kelas lain. Aturan itu tidak dipetakan karena kategori 920 diabaikan, kecuali
920440 yang disebut eksplisit dalam keputusan penulis.

Alasan taksonominya sama dengan 920440: berkas cadangan/VCS tanpa traversal termasuk WEB_SCANNING (aturan T3 di
`configs/label_mapping.yaml`). Di test_sample_500, 920500 tidak pernah cocok, sehingga memetakannya tidak mengubah
`results/regex_full.jsonl`. Bila penulis menerimanya, perubahan itu harus dicatat sebagai penyesuaian setelah run uji.

## 3. Cakupan verifikasi emulasi

| konfigurasi | uji resmi CRS yang bisa dijalankan dari data log | aturan yang dipakai dengan uji / total |
|---|---|---|
| regex_baseline | 985/985 cocok (106 aturan, semua PL) | 55 / 71 |
| regex_full | 1.277/1.277 cocok (124 aturan, semua PL) | 67 / 84 |

Uji yang tidak bisa dijalankan dari data log dilewati: uji yang memakai body POST, permintaan mentah, atau header yang
tidak tercatat. Aturan yang dipakai tetapi tidak punya uji yang bisa dijalankan:

- **regex_baseline:** 932170, 941190, 941200, 941210, 941220, 941230, 941250, 941260, 941290, 941310, 941360, 941370, 942240, 942360, 942540, 942560.
- **regex_full:** daftar yang sama ditambah 933140.

Aturan-aturan ini tetap tercakup secara tidak langsung oleh vektor emas harness C ModSecurity 2.9.15, yang menguji
transformasi dan pencocok frasa (`make golden-check`). Namun keputusan per aturannya tidak diuji terhadap uji resmi.

Berkas uji `933200.yaml` di CRS 4.30.0 memuat `rule_id: 9331200` (salah ketik di sumber CRS). Sejak `4474989`
verifikasi memakai nomor dari nama berkas, sehingga ke-10 uji 933200 ikut dihitung dan semuanya cocok.

Koreksi atas klaim sebelumnya: teks `engine_fix` di `configs/regex_full.yaml` dan pesan commit `dd93c9b` menulis
"diverifikasi 1267/1267 uji regresi resmi CRS untuk semua aturan regex_full". Yang benar adalah angka di tabel di
atas; tidak semua aturan punya uji yang bisa dijalankan.
