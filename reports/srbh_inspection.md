# Inspeksi SR-BH 2020 (Langkah 2)

Dihasilkan otomatis oleh `python -m src.data.inspect_srbh`. Alamat IPv4 pada contoh disamarkan (a.b.x.x).

## 0. Sumber dan integritas

- Berkas: `data/raw/srbh2020/data_capec_multilabel.csv` — Harvard Dataverse doi:10.7910/DVN/OGOIXX, MD5 `173ec515308bdce5aec19cfd5b792596` (cocok dengan metadata Dataverse)
- Pemisah terdeteksi: `,`; encoding: UTF-8 (seluruh byte ASCII)
- Baris data terbaca: **907.815** (publikasi: 907.814); jumlah byte newline di berkas: 907.816 (header + baris data + newline di dalam sel)
- Sel yang mengandung newline (field ber-kutip): tidak ada
- Kolom: 38 = 24 fitur + 14 label (dikenali karena seluruh nilainya 0/1)
- Kolom label "normal" terdeteksi dari data: `000 - Normal` (bernilai 1 tepat saat semua label lain 0 pada 100,0000% baris)

## 1. Daftar kolom dan tipe

Tipe diinferensi dari isi string mentah (semua sel dibaca sebagai teks; string kosong = tidak ada nilai).

| # | kolom | tipe terinferensi | kosong | nilai unik |
|---|---|---|---|---|
| 1 | timestamp | datetime `%d/%b/%Y:%H:%M:%S %z` | 0,00% | 201.534 |
| 2 | src_ip | string | 0,00% | 2 |
| 3 | src_port | integer | 0,00% | 16.603 |
| 4 | dst_ip | string | 0,00% | 2 |
| 5 | dst_port | integer | 0,00% | 2 |
| 6 | request_http_method | string | 0,00% | 18 |
| 7 | request_http_request | string | 0,00% | 350.341 |
| 8 | request_http_protocol | string | 0,00% | 3 |
| 9 | request_user_agent | string | 0,42% | 2.002 |
| 10 | request_referer | string | 67,90% | 2.145 |
| 11 | request_host | string | 0,00% | 9 |
| 12 | request_origin | string | 99,82% | 62 |
| 13 | request_cookie | string | 50,95% | 11.551 |
| 14 | request_content_type | string | 96,86% | 323 |
| 15 | request_accept | string | 57,94% | 75 |
| 16 | request_accept_language | string | 98,25% | 68 |
| 17 | request_accept_encoding | string | 59,65% | 6 |
| 18 | request_do_not_track | integer | 99,92% | 2 |
| 19 | request_connection | string | 46,81% | 5 |
| 20 | request_body | string | 97,05% | 23.763 |
| 21 | response_http_protocol | string | 0,00% | 3 |
| 22 | response_http_status_code | integer | 0,00% | 14 |
| 23 | response_http_status_message | string | 0,00% | 14 |
| 24 | response_content_length | integer | 0,36% | 2.199 |
| 25 | 000 - Normal | biner 0/1 (label) | 0,00% | 2 |
| 26 | 272 - Protocol Manipulation | biner 0/1 (label) | 0,00% | 2 |
| 27 | 242 - Code Injection | biner 0/1 (label) | 0,00% | 2 |
| 28 | 88 - OS Command Injection | biner 0/1 (label) | 0,00% | 2 |
| 29 | 126 - Path Traversal | biner 0/1 (label) | 0,00% | 2 |
| 30 | 66 - SQL Injection | biner 0/1 (label) | 0,00% | 2 |
| 31 | 16 - Dictionary-based Password Attack | biner 0/1 (label) | 0,00% | 2 |
| 32 | 310 - Scanning for Vulnerable Software | biner 0/1 (label) | 0,00% | 2 |
| 33 | 153 - Input Data Manipulation | biner 0/1 (label) | 0,00% | 2 |
| 34 | 248 - Command Injection | biner 0/1 (label) | 0,00% | 2 |
| 35 | 274 - HTTP Verb Tampering | biner 0/1 (label) | 0,00% | 2 |
| 36 | 194 - Fake the Source of Data | biner 0/1 (label) | 0,00% | 2 |
| 37 | 34 - HTTP Response Splitting | biner 0/1 (label) | 0,00% | 2 |
| 38 | 33 - HTTP Request Smuggling | biner 0/1 (label) | 0,00% | 2 |

## 2. Contoh baris

### 5 baris pertama

| kolom | baris 0 | baris 1 | baris 2 | baris 3 | baris 4 |
|---|---|---|---|---|---|
| timestamp | 17/Jul/2020:12:23:34 +0100 | 17/Jul/2020:12:23:41 +0100 | 17/Jul/2020:12:23:51 +0100 | 17/Jul/2020:12:23:51 +0100 | 17/Jul/2020:12:23:58 +0100 |
| src_ip | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x |
| src_port | 55894 | 55897 | 55901 | 55902 | 55903 |
| dst_ip | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x |
| dst_port | 80 | 80 | 80 | 80 | 80 |
| request_http_method | GET | GET | GET | GET | GET |
| request_http_request | / | /blog/index.php/2020/04/04/voluptatum-reprehenderit-maiores-ab-sequi-… | /blog/xmlrpc.php?rsd | / | /blog/index.php/2020/04/04/nihil-tenetur-et-ad-in-dolores/ |
| request_http_protocol | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 |
| request_user_agent | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (K… | Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:36.0) Gecko/20100101 … | Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; WOW64; Trident/4.0… | Mozilla/5.0 (Linux; Android 4.2.2; SM-T110 Build/JDQ39) AppleWebKit/5… | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (K… |
| request_referer | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_host | test-site.com | test-site.com | test-site.com | test-site.com | test-site.com |
| request_origin | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_cookie | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_content_type | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_accept | */* | */* | */* | */* | */* |
| request_accept_language | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_accept_encoding | gzip, deflate | gzip, deflate | gzip, deflate | gzip, deflate | gzip, deflate |
| request_do_not_track | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_connection | keep-alive | keep-alive | keep-alive | keep-alive | keep-alive |
| request_body | ∅ | ∅ | ∅ | ∅ | ∅ |
| response_http_protocol | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 |
| response_http_status_code | 200 | 200 | 200 | 200 | 200 |
| response_http_status_message | OK | OK | OK | OK | OK |
| response_content_length | 25174 | 20862 | 317 | 25174 | 20863 |
| 000 - Normal | 1 | 1 | 1 | 1 | 1 |
| 272 - Protocol Manipulation | 0 | 0 | 0 | 0 | 0 |
| 242 - Code Injection | 0 | 0 | 0 | 0 | 0 |
| 88 - OS Command Injection | 0 | 0 | 0 | 0 | 0 |
| 126 - Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 66 - SQL Injection | 0 | 0 | 0 | 0 | 0 |
| 16 - Dictionary-based Password Attack | 0 | 0 | 0 | 0 | 0 |
| 310 - Scanning for Vulnerable Software | 0 | 0 | 0 | 0 | 0 |
| 153 - Input Data Manipulation | 0 | 0 | 0 | 0 | 0 |
| 248 - Command Injection | 0 | 0 | 0 | 0 | 0 |
| 274 - HTTP Verb Tampering | 0 | 0 | 0 | 0 | 0 |
| 194 - Fake the Source of Data | 0 | 0 | 0 | 0 | 0 |
| 34 - HTTP Response Splitting | 0 | 0 | 0 | 0 | 0 |
| 33 - HTTP Request Smuggling | 0 | 0 | 0 | 0 | 0 |

### 5 baris acak (random_state=42)

| kolom | baris 107655 | baris 503090 | baris 74503 | baris 502943 | baris 356180 |
|---|---|---|---|---|---|
| timestamp | 17/Jul/2020:23:32:51 +0200 | 19/Jul/2020:08:24:50 +0200 | 17/Jul/2020:23:10:15 +0200 | 19/Jul/2020:08:19:11 +0200 | 18/Jul/2020:09:37:23 +0200 |
| src_ip | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x |
| src_port | 50052 | 49714 | 49272 | 49559 | 55369 |
| dst_ip | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x | 172.26.x.x |
| dst_port | 80 | 80 | 80 | 80 | 80 |
| request_http_method | GET | GET | GET | GET | GET |
| request_http_request | /blog/wp-login.php?_wpnonce=7de0abcdc2\&action=logout\&redirect_to=http… | /blog/index.php/2020/03/29%22+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CN… | /blog/index.php/tag/autem-vel-nostrum-enim/HTTP%3A%2F%2Fwww.google.co… | /blog/index.php/2020%25%27%29+UNION+ALL+SELECT+NULL%23/03/29/distinct… | /blog/%2B/uploads/2020/04/755e6d4b-39f2-3314-89a0-c9a4d1bc3143.jpg |
| request_http_protocol | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 |
| request_user_agent | ">\<!--#EXEC cmd="ls /"-->\< | Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0 | Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0 | Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0 | Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0 |
| request_referer | http://test-site.com/blog/index.php/registration/ | http://test-site.com/blog/index.php/page/2/ | ∅ | http://test-site.com/blog/index.php/2020/03/29/distinctio-sequi-offic… | http://test-site.com/blog/index.php/aut-velit-dicta-eaque/ |
| request_host | test-site.com | test-site.com | test-site.com | test-site.com | test-site.com |
| request_origin | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_cookie | wordpress_logged_in_1aefbe2f76edd740f8e362f39da3353b=rafael%7C1595194… | comment_author_url_1aefbe2f76edd740f8e362f39da3353b=http%3A%2F%2Fwww.… | wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_1aefbe2f76… | comment_author_url_1aefbe2f76edd740f8e362f39da3353b=http%3A%2F%2Fwww.… | comment_author_url_1aefbe2f76edd740f8e362f39da3353b=http%3A%2F%2Fwww.… |
| request_content_type | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_accept | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_accept_language | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_accept_encoding | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_do_not_track | ∅ | ∅ | ∅ | ∅ | ∅ |
| request_connection | ∅ | Close | ∅ | Close | ∅ |
| request_body | ∅ | ∅ | ∅ | ∅ | ∅ |
| response_http_protocol | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 | HTTP/1.1 |
| response_http_status_code | 403 | 404 | 404 | 404 | 404 |
| response_http_status_message | Forbidden | Not Found | Not Found | Not Found | Not Found |
| response_content_length | 2951 | 53918 | 276 | 53918 | 276 |
| 000 - Normal | 1 | 0 | 0 | 0 | 1 |
| 272 - Protocol Manipulation | 0 | 0 | 0 | 0 | 0 |
| 242 - Code Injection | 0 | 0 | 0 | 0 | 0 |
| 88 - OS Command Injection | 0 | 0 | 0 | 0 | 0 |
| 126 - Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 66 - SQL Injection | 0 | 1 | 0 | 1 | 0 |
| 16 - Dictionary-based Password Attack | 0 | 0 | 0 | 0 | 0 |
| 310 - Scanning for Vulnerable Software | 0 | 0 | 0 | 0 | 0 |
| 153 - Input Data Manipulation | 0 | 0 | 0 | 0 | 0 |
| 248 - Command Injection | 0 | 0 | 0 | 0 | 0 |
| 274 - HTTP Verb Tampering | 0 | 0 | 0 | 0 | 0 |
| 194 - Fake the Source of Data | 0 | 0 | 1 | 0 | 0 |
| 34 - HTTP Response Splitting | 0 | 0 | 0 | 0 | 0 |
| 33 - HTTP Request Smuggling | 0 | 0 | 0 | 0 | 0 |

## 3. Distribusi label

| label | jumlah | % dari semua baris | % dari baris serangan |
|---|---|---|---|
| 000 - Normal | 525.195 | 57,85% | – |
| 272 - Protocol Manipulation | 9.153 | 1,01% | 2,39% |
| 242 - Code Injection | 15.827 | 1,74% | 4,14% |
| 88 - OS Command Injection | 7.482 | 0,82% | 1,96% |
| 126 - Path Traversal | 20.992 | 2,31% | 5,49% |
| 66 - SQL Injection | 250.311 | 27,57% | 65,42% |
| 16 - Dictionary-based Password Attack | 1.847 | 0,20% | 0,48% |
| 310 - Scanning for Vulnerable Software | 2.718 | 0,30% | 0,71% |
| 153 - Input Data Manipulation | 2.272 | 0,25% | 0,59% |
| 248 - Command Injection | 1 | 0,00% | 0,00% |
| 274 - HTTP Verb Tampering | 5.437 | 0,60% | 1,42% |
| 194 - Fake the Source of Data | 56.145 | 6,18% | 14,67% |
| 34 - HTTP Response Splitting | 19.738 | 2,17% | 5,16% |
| 33 - HTTP Request Smuggling | 1.059 | 0,12% | 0,28% |

- Baris dengan ≥1 label serangan: **382.620** (42,15%); publikasi: 382.619 anomali
- Baris `000 - Normal` = 1: **525.195**; publikasi: 525.195 normal
- Konflik `000 - Normal` = 1 sekaligus punya label serangan: **0**
- Tanpa label sama sekali (normal = 0 dan tidak ada label serangan): **0**

## 4. Multi-label

| jumlah label serangan per baris | baris | % dari semua baris |
|---|---|---|
| 0 | 525.195 | 57,85% |
| 1 | 373.382 | 41,13% |
| 2 | 8.132 | 0,90% |
| 3 | 1.088 | 0,12% |
| 4 | 18 | 0,00% |

- Baris dengan **lebih dari satu** label serangan: **9.238** (1,02% dari semua baris; 2,41% dari baris serangan)

### 20 kombinasi teratas di antara baris multi-label

| kombinasi | baris | % dari baris multi-label | % dari semua baris |
|---|---|---|---|
| 88 - OS Command Injection + 126 - Path Traversal | 2.464 | 26,67% | 0,27% |
| 272 - Protocol Manipulation + 274 - HTTP Verb Tampering | 1.370 | 14,83% | 0,15% |
| 242 - Code Injection + 88 - OS Command Injection | 760 | 8,23% | 0,08% |
| 242 - Code Injection + 66 - SQL Injection | 673 | 7,29% | 0,07% |
| 66 - SQL Injection + 153 - Input Data Manipulation | 612 | 6,62% | 0,07% |
| 34 - HTTP Response Splitting + 33 - HTTP Request Smuggling | 534 | 5,78% | 0,06% |
| 242 - Code Injection + 88 - OS Command Injection + 33 - HTTP Request Smuggling | 510 | 5,52% | 0,06% |
| 88 - OS Command Injection + 126 - Path Traversal + 66 - SQL Injection | 380 | 4,11% | 0,04% |
| 66 - SQL Injection + 16 - Dictionary-based Password Attack | 352 | 3,81% | 0,04% |
| 272 - Protocol Manipulation + 126 - Path Traversal | 267 | 2,89% | 0,03% |
| 272 - Protocol Manipulation + 310 - Scanning for Vulnerable Software | 253 | 2,74% | 0,03% |
| 16 - Dictionary-based Password Attack + 194 - Fake the Source of Data | 162 | 1,75% | 0,02% |
| 272 - Protocol Manipulation + 66 - SQL Injection | 124 | 1,34% | 0,01% |
| 126 - Path Traversal + 153 - Input Data Manipulation | 108 | 1,17% | 0,01% |
| 88 - OS Command Injection + 16 - Dictionary-based Password Attack | 94 | 1,02% | 0,01% |
| 16 - Dictionary-based Password Attack + 153 - Input Data Manipulation | 86 | 0,93% | 0,01% |
| 88 - OS Command Injection + 126 - Path Traversal + 16 - Dictionary-based Password Attack | 78 | 0,84% | 0,01% |
| 16 - Dictionary-based Password Attack + 34 - HTTP Response Splitting | 50 | 0,54% | 0,01% |
| 66 - SQL Injection + 16 - Dictionary-based Password Attack + 153 - Input Data Manipulation | 38 | 0,41% | 0,00% |
| 126 - Path Traversal + 16 - Dictionary-based Password Attack | 34 | 0,37% | 0,00% |

Total kombinasi multi-label berbeda: 48.

### 20 kombinasi teratas di semua baris (termasuk label tunggal)

| kombinasi | baris | % dari semua baris |
|---|---|---|
| (tanpa label serangan) | 525.195 | 57,85% |
| 66 - SQL Injection | 248.093 | 27,33% |
| 194 - Fake the Source of Data | 55.983 | 6,17% |
| 34 - HTTP Response Splitting | 19.134 | 2,11% |
| 126 - Path Traversal | 17.595 | 1,94% |
| 242 - Code Injection | 13.793 | 1,52% |
| 272 - Protocol Manipulation | 7.019 | 0,77% |
| 274 - HTTP Verb Tampering | 4.055 | 0,45% |
| 88 - OS Command Injection | 3.074 | 0,34% |
| 88 - OS Command Injection + 126 - Path Traversal | 2.464 | 0,27% |
| 310 - Scanning for Vulnerable Software | 2.413 | 0,27% |
| 153 - Input Data Manipulation | 1.387 | 0,15% |
| 272 - Protocol Manipulation + 274 - HTTP Verb Tampering | 1.370 | 0,15% |
| 16 - Dictionary-based Password Attack | 836 | 0,09% |
| 242 - Code Injection + 88 - OS Command Injection | 760 | 0,08% |
| 242 - Code Injection + 66 - SQL Injection | 673 | 0,07% |
| 66 - SQL Injection + 153 - Input Data Manipulation | 612 | 0,07% |
| 34 - HTTP Response Splitting + 33 - HTTP Request Smuggling | 534 | 0,06% |
| 242 - Code Injection + 88 - OS Command Injection + 33 - HTTP Request Smuggling | 510 | 0,06% |
| 88 - OS Command Injection + 126 - Path Traversal + 66 - SQL Injection | 380 | 0,04% |

### Matriks ko-okurensi label serangan (diagonal = total label itu)

| CAPEC | 272 | 242 | 88 | 126 | 66 | 16 | 310 | 153 | 248 | 274 | 194 | 34 | 33 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 272 - Protocol Manipulation | 9.153 | 22 | 38 | 289 | 126 | 22 | 276 | 0 | 0 | 1.373 | 0 | 20 | 3 |
| 242 - Code Injection | 22 | 15.827 | 1.297 | 0 | 692 | 67 | 3 | 0 | 0 | 0 | 0 | 0 | 513 |
| 88 - OS Command Injection | 38 | 1.297 | 7.482 | 2.944 | 392 | 210 | 5 | 34 | 0 | 0 | 0 | 0 | 525 |
| 126 - Path Traversal | 289 | 0 | 2.944 | 20.992 | 393 | 130 | 41 | 114 | 0 | 0 | 0 | 0 | 6 |
| 66 - SQL Injection | 126 | 692 | 392 | 393 | 250.311 | 421 | 5 | 650 | 0 | 2 | 0 | 0 | 0 |
| 16 - Dictionary-based Password Attack | 22 | 67 | 210 | 130 | 421 | 1.847 | 0 | 132 | 0 | 9 | 162 | 50 | 0 |
| 310 - Scanning for Vulnerable Software | 276 | 3 | 5 | 41 | 5 | 0 | 2.718 | 1 | 1 | 1 | 0 | 0 | 0 |
| 153 - Input Data Manipulation | 0 | 0 | 34 | 114 | 650 | 132 | 1 | 2.272 | 1 | 0 | 0 | 0 | 0 |
| 248 - Command Injection | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| 274 - HTTP Verb Tampering | 1.373 | 0 | 0 | 0 | 2 | 9 | 1 | 0 | 0 | 5.437 | 0 | 0 | 0 |
| 194 - Fake the Source of Data | 0 | 0 | 0 | 0 | 0 | 162 | 0 | 0 | 0 | 0 | 56.145 | 0 | 0 |
| 34 - HTTP Response Splitting | 20 | 0 | 0 | 0 | 0 | 50 | 0 | 0 | 0 | 0 | 0 | 19.738 | 534 |
| 33 - HTTP Request Smuggling | 3 | 513 | 525 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 534 | 1.059 |

## 5. Profil tambahan untuk langkah 4–8 (fakta, belum keputusan)

### Timestamp
- Contoh nilai mentah: `17/Jul/2020:12:23:34 +0100`, `18/Jul/2020:17:49:24 +0200`, `29/Jul/2020:22:29:00 +0100`
- Format terdeteksi: `%d/%b/%Y:%H:%M:%S %z`; gagal diurai: 2; offset zona waktu: `+0200` (541.976), `+0100` (365.837)
- Rentang: 2020-07-17 11:23:34+00:00 s.d. 2020-11-01 21:59:51+00:00
- Baris dengan pecahan detik: 0,00%; nilai unik: 201.430
- Urut naik di berkas: tidak; maksimum baris pada detik yang sama: 103

### src_ip
- IP unik: 2; IP dengan ≥1 serangan: 1; IP campuran (normal dan serangan): 1 (menyumbang 100,00% baris)
- 10 IP teratas menyumbang 100,00% baris:

| IP (disamarkan) | baris | % total | % baris IP itu yang serangan |
|---|---|---|---|
| 172.26.x.x | 907.813 | 100,00% | 42,15% |
| ∅ | 2 | 0,00% | 0,00% |

### request_http_request
- Mengandung `?` (query string): 11,33%; diawali `/`: 99,95%; URI absolut `http(s)://`: 6; panjang maksimum: 681 karakter
- Contoh URI yang tidak diawali `/`: `www.google.com:80` (453), `http://165.175.x.x:41200/pass` (6), `` (2), `%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini` (1), `?feed=atom` (1)

### request_body (tidak ikut terekam di Combined Log Format)
- Body tidak kosong: 26.743 baris (2,95%); di antara baris serangan: 6,18%

| label serangan | % baris berlabel ini yang punya body |
|---|---|
| 272 - Protocol Manipulation | 13,71% |
| 242 - Code Injection | 12,35% |
| 88 - OS Command Injection | 61,20% |
| 126 - Path Traversal | 12,51% |
| 66 - SQL Injection | 3,95% |
| 16 - Dictionary-based Password Attack | 100,00% |
| 310 - Scanning for Vulnerable Software | 0,11% |
| 153 - Input Data Manipulation | 99,96% |
| 248 - Command Injection | 0,00% |
| 274 - HTTP Verb Tampering | 18,82% |
| 194 - Fake the Source of Data | 5,66% |
| 34 - HTTP Response Splitting | 5,54% |
| 33 - HTTP Request Smuggling | 55,24% |

### request_http_method (18 nilai unik, 12 teratas)

| nilai | baris | % |
|---|---|---|
| GET | 869.268 | 95,75% |
| POST | 28.381 | 3,13% |
| TRACE | 2.340 | 0,26% |
| OPTIONS | 1.284 | 0,14% |
| HEAD | 1.103 | 0,12% |
| TRACK | 906 | 0,10% |
| LOCK | 453 | 0,05% |
| PROPPATCH | 453 | 0,05% |
| PROPFIND | 453 | 0,05% |
| MOVE | 453 | 0,05% |
| MKCOL | 453 | 0,05% |
| PATCH | 453 | 0,05% |

### request_http_protocol (3 nilai unik, 12 teratas)

| nilai | baris | % |
|---|---|---|
| HTTP/1.1 | 907.082 | 99,92% |
| HTTP/1.0 | 731 | 0,08% |
| ∅ | 2 | 0,00% |

### response_http_status_code (14 nilai unik, 12 teratas)

| nilai | baris | % |
|---|---|---|
| 200 | 436.532 | 48,09% |
| 404 | 431.380 | 47,52% |
| 301 | 26.347 | 2,90% |
| 400 | 5.669 | 0,62% |
| 405 | 3.998 | 0,44% |
| 302 | 1.170 | 0,13% |
| 403 | 1.141 | 0,13% |
| 500 | 808 | 0,09% |
| 501 | 296 | 0,03% |
| 429 | 294 | 0,03% |
| 206 | 153 | 0,02% |
| 304 | 20 | 0,00% |

- `response_content_length`: kosong 0,36%, nilai unik 2.199
- `request_user_agent`: kosong 0,42%, nilai unik 2.002
- `request_referer`: kosong 67,90%, nilai unik 2.145
- `dst_ip`: kosong 0,00%, nilai unik 2
- `request_host`: kosong 0,00%, nilai unik 9

