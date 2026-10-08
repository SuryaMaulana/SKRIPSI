# Pilot deep agent vs LLM tunggal (30 baris, label benar dari test)

Run E: `agent-20261007T164716Z-725069c` (commit d1abba5, dirty=False, model openai/gpt-4.1-nano). C: `llm_single-20261007T161203Z-6ce9f30`.

## Hasil per baris

| # | id | benar | C | E | status E | putaran | tolak | pengingat | 4 sub-agen | LLM E | alat E | token E (in/out) | latensi E (s) | biaya E ($) | token C (in/out) | latensi C (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `srbh-08bedb024d7ae9ea` | XSS | XSS ✓ | XSS ✓ | verification_failed | 2 | 2 | 1 | ya | 28 | 34 | 87496/2389 | 51,2 | 0.00440 | 958/68 | 1,71 |
| 2 | `srbh-f60769f8678a6831` | NORMAL | NORMAL ✓ | NORMAL ✓ | verification_failed | 2 | 2 | 1 | ya | 18 | 19 | 51215/1341 | 36,2 | 0.00255 | 902/102 | 2,07 |
| 3 | `srbh-aec85e4d0aa12577` | PATH_TRAVERSAL | WEB_SCANNING ✗ | NORMAL ✗ | ok | 1 | 0 | 0 | ya | 11 | 14 | 29749/1081 | 15,6 | 0.00171 | 913/117 | 1,71 |
| 4 | `srbh-231956c67a457b5a` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 0 | ya | 14 | 18 | 39127/1216 | 19,7 | 0.00228 | 931/91 | 1,41 |
| 5 | `srbh-1c7553b2e8c02ae7` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 0 | ya | 16 | 17 | 42223/980 | 20,7 | 0.00219 | 927/70 | 1,90 |
| 6 | `srbh-0c2ab3c6ff0f0cef` | NORMAL | NORMAL ✓ | NORMAL ✓ | verification_failed | 2 | 2 | 0 | ya | 21 | 17 | 58723/1232 | 26,5 | 0.00293 | 922/118 | 2,00 |
| 7 | `srbh-fae0e1ba315fa2c1` | WEB_SCANNING | WEB_SCANNING ✓ | NORMAL ✗ | verification_failed | 2 | 2 | 0 | ya | 20 | 18 | 57400/1359 | 33,5 | 0.00315 | 943/85 | 1,74 |
| 8 | `srbh-721f5c0f1db5a53c` | CMD_INJECTION | CMD_INJECTION ✓ | CMD_INJECTION ✓ | ok | 1 | 0 | 0 | ya | 13 | 15 | 36427/1265 | 20,1 | 0.00207 | 945/73 | 1,94 |
| 9 | `srbh-aa5f0e59a07f196a` | NORMAL | NORMAL ✓ | NORMAL ✓ | verification_failed | 2 | 2 | 2 | ya | 19 | 23 | 58232/2400 | 34,7 | 0.00337 | 955/115 | 1,87 |
| 10 | `srbh-01b00fcbf8064bef` | XSS | XSS ✓ | PARSE_ERROR ✗ | PARSE_ERROR | 0 | 0 | 0 | tidak | 20 | 20 | 97243/1018 | 30,0 | 0.00323 | 890/63 | 1,95 |
| 11 | `srbh-1567934be785b9ae` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 1 | 0 | 1 | tidak | 16 | 12 | 48160/1294 | 25,7 | 0.00249 | 984/123 | 1,72 |
| 12 | `srbh-daf276f8cabe83d8` | WEB_SCANNING | WEB_SCANNING ✓ | WEB_SCANNING ✓ | verification_failed | 2 | 2 | 0 | ya | 19 | 21 | 48958/1096 | 22,2 | 0.00240 | 884/63 | 1,56 |
| 13 | `srbh-39eb58ec5a725284` | NORMAL | NORMAL ✓ | NORMAL ✓ | verification_failed | 2 | 2 | 2 | ya | 26 | 26 | 88001/2143 | 48,2 | 0.00429 | 956/136 | 2,41 |
| 14 | `srbh-eafc5a26bcac8907` | SQLI | SQLI ✓ | SQLI ✓ | ok | 2 | 1 | 0 | ya | 19 | 19 | 55859/1624 | 40,9 | 0.00302 | 971/77 | 1,42 |
| 15 | `srbh-e6417922b662e2ac` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 0 | ya | 14 | 17 | 39963/1261 | 30,5 | 0.00236 | 958/61 | 1,24 |
| 16 | `srbh-36368afe504e2662` | CMD_INJECTION | PATH_TRAVERSAL ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 0 | ya | 12 | 15 | 32284/1222 | 21,9 | 0.00189 | 955/86 | 1,46 |
| 17 | `srbh-b37943f5082e45b8` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 1 | 0 | 0 | ya | 13 | 12 | 35806/946 | 22,7 | 0.00189 | 985/130 | 1,99 |
| 18 | `srbh-7724b5385849d05c` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 0 | ya | 13 | 15 | 35125/1014 | 15,5 | 0.00183 | 926/85 | 1,20 |
| 19 | `srbh-30cb1c9ddb21b535` | WEB_SCANNING | NORMAL ✗ | NORMAL ✗ | verification_failed | 2 | 2 | 0 | ya | 19 | 20 | 57204/1625 | 24,1 | 0.00290 | 1003/81 | 1,37 |
| 20 | `srbh-89e8529757199934` | SQLI | SQLI ✓ | SQLI ✓ | verification_failed | 2 | 2 | 0 | ya | 22 | 24 | 60118/2040 | 34,7 | 0.00337 | 994/72 | 1,34 |
| 21 | `srbh-e96613aeb264209a` | WEB_SCANNING | PATH_TRAVERSAL ✗ (C pilot: NORMAL) | PATH_TRAVERSAL ✗ | ok | 2 | 1 | 0 | ya | 20 | 25 | 54817/2002 | 30,6 | 0.00347 | 930/68 | 1,75 |
| 22 | `srbh-53dcb82282e959b9` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | verification_failed | 2 | 2 | 1 | ya | 20 | 18 | 58066/1448 | 31,5 | 0.00304 | 993/123 | 2,30 |
| 23 | `srbh-8002b48db2cdb197` | XSS | XSS ✓ | PARSE_ERROR ✗ | PARSE_ERROR | 0 | 0 | 4 | tidak | 19 | 18 | 76881/659 | 22,5 | 0.00257 | 886/58 | 1,42 |
| 24 | `srbh-098b9c2443ef7421` | SQLI | SQLI ✓ | SQLI ✓ | verification_failed | 2 | 2 | 0 | ya | 24 | 30 | 67028/1202 | 35,1 | 0.00319 | 1112/108 | 1,82 |
| 25 | `srbh-c75bb11bfd646555` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 2 | 1 | 1 | ya | 28 | 31 | 71114/1820 | 41,4 | 0.00352 | 969/116 | 5,31 |
| 26 | `srbh-a7c36c09bcd7bf3b` | CMD_INJECTION | CMD_INJECTION ✓ | PARSE_ERROR ✗ | PARSE_ERROR | 0 | 0 | 4 | tidak | 14 | 11 | 57334/562 | 20,0 | 0.00187 | 905/73 | 1,22 |
| 27 | `srbh-601629e62f22a62d` | WEB_SCANNING | NORMAL ✗ | NORMAL ✗ | verification_failed | 2 | 2 | 0 | ya | 20 | 21 | 55219/1256 | 37,4 | 0.00265 | 920/111 | 1,48 |
| 28 | `srbh-3e7a9f9255a08d1d` | CMD_INJECTION | PATH_TRAVERSAL ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 0 | ya | 13 | 14 | 35501/1275 | 18,5 | 0.00224 | 934/65 | 1,27 |
| 29 | `srbh-fa2a8c6062469836` | CMD_INJECTION | SQLI ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 0 | ya | 14 | 16 | 39478/1333 | 19,1 | 0.00217 | 929/71 | 1,60 |
| 30 | `srbh-b90bd4ea89d4b716` | NORMAL | NORMAL ✓ | NORMAL ✓ | verification_failed | 2 | 2 | 1 | ya | 38 | 40 | 93788/1939 | 53,0 | 0.00434 | 970/108 | 1,87 |

## Ringkasan

| metrik | C (500 penuh) | C pilot | E |
|---|---|---|---|
| benar (dari 30) | 23 | 23 | 19 |
| macro-F1 pada 30 baris | 0,747 | 0,746 | 0,624 |
| evidence literal | 35/46 = 0,761 | 36/46 = 0,783 | 28/44 = 0,636 |
| token masukan per baris (rerata) | 948 | 948 | 55618 |
| token keluaran per baris (rerata) | 91 | 96 | 1401 |
| latensi median (s) | 1,71 | 1,52 | 28,22 |
| latensi p95 (s) | 2,36 | 2,62 | 49,84 |
| biaya total ($) | 0.00393 | 0.00400 | 0.08336 |
| panggilan LLM per baris (rerata) | 1,0 | 1,0 | 18,8 |
| pemanggilan alat per baris (rerata) | — | — | 20,0 |

## Verifikasi dan orkestrasi (E)

- Status: ok 14, verification_failed 13, verification_skipped 0, PARSE_ERROR 3
- Orkestrator mendelegasikan ke keempat sub-agen: 26/30 baris.
- Putusan verifikasi: 43; ditolak 29 kali di 16 baris (penilaian LLM verifikator: 4, evidence/skema (deterministik): 14, evidence/skema + penilaian LLM: 10, verifikator tanpa putusan + evidence/skema: 1).
- Baris dengan 2 putaran: 16; label berubah setelah penolakan: 1 baris.
- Pengingat prosedur: 18; pemanggilan sub-agen yang ditahan guard: 9; batas panggilan sub-agen tercapai: 1.
- E benar di baris yang C (500 penuh) salah: 0 (—); E salah di baris yang C (500 penuh) benar: 4 (`srbh-fae0e1ba315fa2c1`, `srbh-01b00fcbf8064bef`, `srbh-8002b48db2cdb197`, `srbh-a7c36c09bcd7bf3b`).
- Label E = C (500 penuh): 24/30.

## Baris yang ditolak Verifikasi

- `srbh-08bedb024d7ae9ea` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi XSS tidak sesuai karena log menunjukkan adanya URL encoding dari skrip dan parameter yang tidak secara eksplisit mengandung tag <script> atau alert(1); dalam bentuk yang langsung dapat die
- `srbh-08bedb024d7ae9ea` putaran 2 (klasifikasi ke-2): ditolak; LLM tolak; alasan: Klasifikasi XSS tidak sesuai karena evidence menunjukkan URL encoding dari skrip berbahaya, bukan skrip langsung yang dieksekusi. Selain itu, schema_check menunjukkan bahwa evidence tidak ditemukan se
  - riwayat label klasifikasi: XSS -> XSS; label akhir XSS (klasifikasi ke-2), status verification_failed, benar XSS
- `srbh-f60769f8678a6831` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Keluaran klasifikasi sesuai dengan log dan definisi kelas NORMAL. Evidence menunjukkan permintaan yang wajar ke URL feed RSS tanpa indikasi serangan. | evidence tidak ditemukan di baris log: path: /blog/index.php/tag/nihil-alias-ab/feed/
- `srbh-f60769f8678a6831` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan log yang diberikan, serta schema valid. | evidence tidak ditemukan di baris log: Permintaan ke URL feed RSS yang wajar tanpa indikasi serangan
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar NORMAL
- `srbh-0c2ab3c6ff0f0cef` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Klasifikasi sesuai dengan evidence dan definisi kelas, yaitu NORMAL, karena tidak ditemukan pola mencurigakan. | evidence tidak ditemukan di baris log: Tidak ada pola mencurigakan dalam path atau user agent
- `srbh-0c2ab3c6ff0f0cef` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan log yang diberikan, tidak ada indikasi serangan. | evidence tidak ditemukan di baris log: Tidak ada pola mencurigakan dalam path atau user agent
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar NORMAL
- `srbh-fae0e1ba315fa2c1` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi tidak konsisten dengan evidence dan log. Evidence menunjukkan adanya metode MKCOL yang tidak umum dan tidak menunjukkan bukti serangan tertentu, sedangkan klasifikasi menyatakan NORMAL. | evidence tidak ditemukan di baris log: Method is not allowed by policy
- `srbh-fae0e1ba315fa2c1` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan definisi kelas, tidak ditemukan indikasi serangan. | evidence tidak ditemukan di baris log: Method is not allowed by policy
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar WEB_SCANNING
- `srbh-aa5f0e59a07f196a` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan log dan evidence yang ada, tidak ditemukan indikasi serangan atau pola mencurigakan. | evidence tidak ditemukan di baris log: path: /blog/wp-content/uploads/2020/6-2/914665e4-4fbd-3377-9747-d24ebaabf676-300x240.png; referer: http://test-site.com/blog/index.php/2020/04/04/hic-porro-nihil
- `srbh-aa5f0e59a07f196a` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan log yang menunjukkan permintaan sah tanpa indikasi serangan. Evidence lengkap dan konsisten dengan definisi kelas. | evidence tidak ditemukan di baris log: path: /blog/wp-content/uploads/2020/6-2/914665e4-4fbd-3377-9747-d24ebaabf676-300x240.png; referer: http://test-site.com/blog/index.php/2020/04/04/hic-porro-nihil
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar NORMAL
- `srbh-daf276f8cabe83d8` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi tidak lolos schema check karena evidence tidak ditemukan dalam log. | Evidence 'User-Agent associated with security scanner' tidak ada dalam log. | Evidence 'metode non_standar null' tidak ada dalam log. | Evidence 'ekstensi cadangan null' tidak ada dalam log. | evidence tidak ditemukan di baris log: User-Agent associated with security scanner; metode non_standar null; ekstensi cadangan null
- `srbh-daf276f8cabe83d8` putaran 2 (klasifikasi ke-2): ditolak; LLM tolak; alasan: Item evidence tidak ditemukan dalam log. | evidence tidak ditemukan di baris log: User-Agent associated with security scanner
  - riwayat label klasifikasi: WEB_SCANNING -> WEB_SCANNING; label akhir WEB_SCANNING (klasifikasi ke-2), status verification_failed, benar WEB_SCANNING
- `srbh-39eb58ec5a725284` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan log yang diberikan, tidak ditemukan indikasi serangan atau aktivitas mencurigakan. | evidence tidak ditemukan di baris log: path: /blog/wp-content/uploads/2020/04/02020950-6e37-3272-9dbf-3093969e3563-300x200.jpg; user_agent: Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Fire
- `srbh-39eb58ec5a725284` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan log yang menunjukkan permintaan normal untuk file gambar tanpa indikasi serangan. | evidence tidak ditemukan di baris log: path: /blog/wp-content/uploads/2020/04/02020950-6e37-3272-9dbf-3093969e3563-300x200.jpg; user_agent: Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Fire
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar NORMAL
- `srbh-eafc5a26bcac8907` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi tidak sesuai karena log menunjukkan upaya SQL Injection, tetapi label yang diberikan adalah 'SQLI' yang benar, namun ada ketidaksesuaian dalam penilaian sebelumnya. Perlu verifikasi ulang.
- `srbh-eafc5a26bcac8907` putaran 2 (klasifikasi ke-2): lolos; LLM lolos; alasan: Keluaran sesuai skema dan evidence ditemukan di log.
  - riwayat label klasifikasi: SQLI -> SQLI; label akhir SQLI (klasifikasi ke-2), status ok, benar SQLI
- `srbh-30cb1c9ddb21b535` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan definisi kelas. | evidence tidak ditemukan di baris log: Method: TRACK
- `srbh-30cb1c9ddb21b535` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan definisi kelas, serta schema_check valid. | evidence tidak ditemukan di baris log: Method: TRACK; Tidak ada bukti penyisipan SQL, skrip XSS, path traversal, command injection, atau pemindaian
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar WEB_SCANNING
- `srbh-89e8529757199934` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Keluaran schema_check gagal, evidence path tidak ditemukan. | evidence tidak ditemukan di baris log: path: /blog/index.php/2020%25%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C
- `srbh-89e8529757199934` putaran 2 (klasifikasi ke-2): ditolak; LLM tolak; alasan: Klasifikasi tidak sesuai dengan evidence yang tidak ditemukan di log. | Evidence yang diindikasikan tidak ada dalam log. | evidence tidak ditemukan di baris log: UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
  - riwayat label klasifikasi: SQLI -> SQLI; label akhir SQLI (klasifikasi ke-2), status verification_failed, benar SQLI
- `srbh-e96613aeb264209a` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi 'NORMAL' tidak sesuai dengan evidence yang menunjukkan upaya akses file konfigurasi server. Evidence mengindikasikan kemungkinan serangan LFI. | evidence tidak ditemukan di baris log: Restricted File Access Attempt; tag: attack-lfi; cocok: .htaccess
- `srbh-e96613aeb264209a` putaran 2 (klasifikasi ke-2): lolos; LLM lolos; alasan: Klasifikasi PATH_TRAVERSAL sesuai dengan evidence '.htaccess' yang menunjukkan upaya mengakses file konfigurasi server, yang merupakan ciri dari serangan Path Traversal.
  - riwayat label klasifikasi: NORMAL -> PATH_TRAVERSAL; label akhir PATH_TRAVERSAL (klasifikasi ke-2), status ok, benar WEB_SCANNING
- `srbh-53dcb82282e959b9` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Klasifikasi PATH_TRAVERSAL tidak sesuai dengan evidence yang diberikan. Evidence menunjukkan tidak ada indikasi traversal path dalam log. | evidence tidak ditemukan di baris log: Path Traversal Attack (/../) or (/.../) detected in request URI; encoded path segments indicating traversal attempt
- `srbh-53dcb82282e959b9` putaran 2 (klasifikasi ke-2): ditolak; LLM tolak; alasan: Klasifikasi PATH_TRAVERSAL tidak sesuai karena evidence menunjukkan upaya akses path traversal dengan encoding, namun label yang diberikan adalah PATH_TRAVERSAL dan tidak ada indikasi label salah.
  - riwayat label klasifikasi: PATH_TRAVERSAL -> PATH_TRAVERSAL; label akhir PATH_TRAVERSAL (klasifikasi ke-2), status verification_failed, benar PATH_TRAVERSAL
- `srbh-098b9c2443ef7421` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Keluaran schema_check tidak valid. | Item evidence 'select+count(*)' tidak ditemukan di log. | Label 'SQLI' tidak konsisten dengan evidence dan definisi kelas. | evidence tidak ditemukan di baris log: select+count(*)
- `srbh-098b9c2443ef7421` putaran 2 (klasifikasi ke-2): ditolak; LLM tolak; alasan: Evidence 'select+count(*)' tidak ditemukan dalam log. | evidence tidak ditemukan di baris log: select+count(*)
  - riwayat label klasifikasi: SQLI -> SQLI; label akhir SQLI (klasifikasi ke-2), status verification_failed, benar SQLI
- `srbh-c75bb11bfd646555` putaran 1 (klasifikasi ke-1): ditolak; LLM lolos; alasan: Klasifikasi PATH_TRAVERSAL sesuai dengan evidence dan definisi kelas. Evidence menunjukkan percobaan akses path traversal dengan encoding umum. | evidence tidak ditemukan di baris log: Path Traversal Attack (/../) or (/.../)
- `srbh-c75bb11bfd646555` putaran 2 (klasifikasi ke-2): lolos; LLM lolos; alasan: Schema valid dan evidence ditemukan sesuai log dan definisi PATH_TRAVERSAL.
  - riwayat label klasifikasi: PATH_TRAVERSAL -> PATH_TRAVERSAL; label akhir PATH_TRAVERSAL (klasifikasi ke-2), status ok, benar PATH_TRAVERSAL
- `srbh-601629e62f22a62d` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: Label 'NORMAL' tidak sesuai dengan evidence 'UNLOCK' yang menunjukkan metode HTTP tidak standar dan kemungkinan permintaan tidak sah. | evidence tidak ditemukan di baris log: Method is not allowed by policy
- `srbh-601629e62f22a62d` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan definisi kelas. Evidence menunjukkan metode HTTP tidak standar dan tidak indikasi serangan. | evidence tidak ditemukan di baris log: Method is not allowed by policy
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar WEB_SCANNING
- `srbh-b90bd4ea89d4b716` putaran 1 (klasifikasi ke-1): ditolak; LLM tolak; alasan: verifikator tidak memberi putusan | evidence tidak ditemukan di baris log: path: /blog/index.php/wp-json/oembed/%29/embed; query: format=xml&url=http%3A%2F%2Ftest-site.com%2Fblog%2Findex.php%2Fvitae-dolores-quidem-possimus-aut-voluptati
- `srbh-b90bd4ea89d4b716` putaran 2 (klasifikasi ke-2): ditolak; LLM lolos; alasan: Klasifikasi 'NORMAL' sesuai dengan evidence dan definisi kelas. Tidak ditemukan pola serangan dari evidence yang ada. | evidence tidak ditemukan di baris log: path: /blog/index.php/wp-json/oembed/%29/embed; query: format=xml&url=http%3A%2F%2Ftest-site.com%2Fblog%2Findex.php%2Fvitae-dolores-quidem-possimus-aut-voluptati
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status verification_failed, benar NORMAL
