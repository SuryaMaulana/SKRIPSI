# Validasi deep agent v2 vs LLM tunggal (srbh_val) (30 baris, label benar dari val)

Run E: `agent-20261007T185745Z-3988205` (commit ed938d1, dirty=False, model openai/gpt-4.1-nano). C: `llm_single-20261007T201505Z-3988205`.

## Hasil per baris

| # | id | benar | C | E | status E | putaran | tolak | pengingat | 4 sub-agen | LLM E | alat E | token E (in/out) | latensi E (s) | biaya E ($) | token C (in/out) | latensi C (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `srbh-8e320db8fbdf94dd` | XSS | XSS ✓ | XSS ✓ | verification_failed | 2 | 2 | 0 | ya | 14 | 21 | 24424/1089 | 21,1 | 0.00161 | 900/88 | 1,50 |
| 2 | `srbh-876773cf5ec89e0d` | WEB_SCANNING | WEB_SCANNING ✓ | WEB_SCANNING ✓ | ok | 1 | 0 | 0 | ya | 11 | 15 | 15966/804 | 16,5 | 0.00126 | 883/61 | 1,18 |
| 3 | `srbh-7621b818df20ee66` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 17700/882 | 19,7 | 0.00135 | 980/116 | 1,47 |
| 4 | `srbh-9e2c0ddb866ac924` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 2 | 1 | 1 | ya | 16 | 20 | 39332/2155 | 34,3 | 0.00253 | 1007/160 | 1,76 |
| 5 | `srbh-fb4acf1be8025c2f` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 1 | 0 | 1 | ya | 14 | 14 | 20787/820 | 20,0 | 0.00163 | 910/88 | 1,44 |
| 6 | `srbh-22fd61bf1c4fe591` | PATH_TRAVERSAL | PATH_TRAVERSAL ✓ | PATH_TRAVERSAL ✓ | ok | 1 | 0 | 0 | tidak | 5 | 5 | 11228/570 | 12,1 | 0.00072 | 971/117 | 1,53 |
| 7 | `srbh-8e256d45987c63ac` | PATH_TRAVERSAL | NORMAL ✗ | NORMAL ✗ | ok | 2 | 1 | 2 | tidak | 14 | 17 | 28895/1035 | 26,1 | 0.00163 | 927/111 | 1,53 |
| 8 | `srbh-914b8637322cfb43` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 0 | ya | 12 | 14 | 22065/1195 | 22,8 | 0.00172 | 970/73 | 1,60 |
| 9 | `srbh-bb231169ee3e99de` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 0 | ya | 12 | 14 | 18269/872 | 17,9 | 0.00134 | 957/68 | 1,27 |
| 10 | `srbh-9294691b79150b38` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 2 | ya | 14 | 16 | 27212/1359 | 27,3 | 0.00188 | 959/62 | 1,54 |
| 11 | `srbh-e8ade5ac86f3cd10` | XSS | XSS ✓ | XSS ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 17126/908 | 18,7 | 0.00138 | 933/80 | 1,34 |
| 12 | `srbh-2b5e984e87acdfa2` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 0 | ya | 10 | 16 | 17091/1108 | 20,3 | 0.00143 | 933/72 | 1,31 |
| 13 | `srbh-39f746f14245bde4` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 2 | tidak | 11 | 12 | 315553/66328 | 976,6 | 0.03988 | 925/61 | 1,20 |
| 14 | `srbh-3fe95c5897af8b0c` | SQLI | NORMAL ✗ | NORMAL ✗ | ok | 1 | 0 | 0 | ya | 13 | 15 | 24496/1562 | 30,1 | 0.00186 | 961/96 | 1,16 |
| 15 | `srbh-fe93be6a36886a25` | CMD_INJECTION | SQLI ✗ | CMD_INJECTION ✓ | ok | 1 | 0 | 0 | ya | 12 | 16 | 21827/1289 | 27,1 | 0.00165 | 983/108 | 1,44 |
| 16 | `srbh-b18ebdca6394eb6b` | CMD_INJECTION | WEB_SCANNING ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 0 | ya | 10 | 14 | 16526/1140 | 17,9 | 0.00141 | 928/80 | 1,48 |
| 17 | `srbh-40532897055c99e8` | CMD_INJECTION | SQLI ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 2 | ya | 13 | 17 | 25314/1510 | 27,2 | 0.00217 | 927/68 | 1,13 |
| 18 | `srbh-af9c7b1ac42dce17` | CMD_INJECTION | CMD_INJECTION ✓ | CMD_INJECTION ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 18543/1398 | 21,6 | 0.00176 | 946/63 | 1,12 |
| 19 | `srbh-3f285081547c2da3` | CMD_INJECTION | CMD_INJECTION ✓ | CMD_INJECTION ✓ | ok | 2 | 1 | 0 | ya | 14 | 23 | 24673/1155 | 22,9 | 0.00162 | 931/84 | 1,19 |
| 20 | `srbh-44869ede21c898f8` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 0 | ya | 11 | 15 | 16886/1100 | 17,3 | 0.00137 | 936/78 | 1,40 |
| 21 | `srbh-e1880cb7bada7b50` | SQLI | SQLI ✓ | SQLI ✓ | ok | 1 | 0 | 2 | ya | 13 | 15 | 27080/1842 | 29,6 | 0.00209 | 1002/59 | 1,15 |
| 22 | `srbh-db4860ab7fec0af2` | NORMAL | NORMAL ✓ | NORMAL ✓ | ok | 1 | 0 | 0 | ya | 11 | 15 | 16532/885 | 18,8 | 0.00133 | 908/92 | 1,28 |
| 23 | `srbh-d8eb05c094ccbf5b` | WEB_SCANNING | PATH_TRAVERSAL ✗ | PATH_TRAVERSAL ✗ | ok | 1 | 0 | 0 | ya | 11 | 15 | 17055/1000 | 20,3 | 0.00137 | 909/73 | 1,30 |
| 24 | `srbh-dd8866175216be25` | WEB_SCANNING | NORMAL ✗ | NORMAL ✗ | ok | 1 | 0 | 0 | ya | 11 | 15 | 17358/1030 | 22,4 | 0.00137 | 913/96 | 1,71 |
| 25 | `srbh-952a34419a1274ba` | WEB_SCANNING | NORMAL ✗ | NORMAL ✗ | ok | 1 | 0 | 0 | ya | 11 | 16 | 16343/911 | 17,6 | 0.00132 | 909/107 | 1,58 |
| 26 | `srbh-789cd2f4515a1b15` | WEB_SCANNING | NORMAL ✗ | NORMAL ✗ | ok | 1 | 0 | 0 | ya | 11 | 15 | 17324/1080 | 16,9 | 0.00141 | 908/92 | 2,03 |
| 27 | `srbh-05fc5ab87877e066` | NORMAL | NORMAL ✓ | PARSE_ERROR ✗ | PARSE_ERROR | 0 | 0 | 4 | tidak | 5 | 0 | 339164/163840 | 3051,5 | 0.08146 | 951/146 | 1,49 |
| 28 | `srbh-8fcb735d6118334d` | NORMAL | NORMAL ✓ | NORMAL ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 17582/1173 | 23,4 | 0.00165 | 935/129 | 1,75 |
| 29 | `srbh-9bc8037170253574` | NORMAL | NORMAL ✓ | NORMAL ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 16920/1038 | 20,6 | 0.00141 | 917/111 | 1,57 |
| 30 | `srbh-c126bde1821eddb4` | NORMAL | NORMAL ✓ | NORMAL ✓ | ok | 1 | 0 | 0 | ya | 11 | 16 | 17417/1124 | 19,3 | 0.00148 | 941/63 | 3,36 |

## Ringkasan

| metrik | C | E |
|---|---|---|
| benar (dari 30) | 21 | 21 |
| macro-F1 pada 30 baris | 0,675 | 0,702 |
| evidence literal | 39/47 = 0,830 | 45/46 = 0,978 |
| token masukan per baris (rerata) | 939 | 40890 |
| token keluaran per baris (rerata) | 90 | 8740 |
| latensi median (s) | 1,46 | 20,89 |
| latensi p95 (s) | 1,91 | 552,55 |
| biaya total ($) | 0.00390 | 0.16508 |
| panggilan LLM per baris (rerata) | 1,0 | 11,5 |
| pemanggilan alat per baris (rerata) | — | 15,0 |

## Verifikasi dan orkestrasi (E)

- Status: ok 28, verification_failed 1, verification_skipped 0, PARSE_ERROR 1
- Orkestrator mendelegasikan ke keempat sub-agen: 26/30 baris.
- Putusan verifikasi: 33; ditolak 5 kali di 4 baris (evidence/skema (deterministik): 5).
- Baris dengan 2 putaran: 4; label berubah setelah penolakan: 0 baris.
- Pengingat prosedur: 16; pemanggilan sub-agen yang ditahan guard: 4; batas panggilan sub-agen tercapai: 0.
- E benar di baris yang C salah: 1 (`srbh-fe93be6a36886a25`); E salah di baris yang C benar: 1 (`srbh-05fc5ab87877e066`).
- Label E = C: 26/30.

## Baris yang ditolak Verifikasi

- `srbh-8e320db8fbdf94dd` putaran 1 (klasifikasi ke-1): ditolak; alasan: evidence tidak ditemukan di baris log: "><script>alert("XSS")</script><"; REQUEST_HEADERS:Referer; cocok: <script>
- `srbh-8e320db8fbdf94dd` putaran 2 (klasifikasi ke-2): ditolak; alasan: evidence tidak ditemukan di baris log: "><script>alert("XSS")</script><"
  - riwayat label klasifikasi: XSS -> XSS; label akhir XSS (klasifikasi ke-2), status verification_failed, benar XSS
- `srbh-9e2c0ddb866ac924` putaran 1 (klasifikasi ke-1): ditolak; alasan: evidence tidak ditemukan di baris log: Path Traversal Attack (/../) or (/.../)
- `srbh-9e2c0ddb866ac924` putaran 2 (klasifikasi ke-2): lolos; alasan: 
  - riwayat label klasifikasi: PATH_TRAVERSAL -> PATH_TRAVERSAL; label akhir PATH_TRAVERSAL (klasifikasi ke-2), status ok, benar PATH_TRAVERSAL
- `srbh-8e256d45987c63ac` putaran 1 (klasifikasi ke-1): ditolak; alasan: evidence tidak ditemukan di baris log: 
- `srbh-8e256d45987c63ac` putaran 2 (klasifikasi ke-2): lolos; alasan: 
  - riwayat label klasifikasi: NORMAL -> NORMAL; label akhir NORMAL (klasifikasi ke-2), status ok, benar PATH_TRAVERSAL
- `srbh-3f285081547c2da3` putaran 1 (klasifikasi ke-1): ditolak; alasan: evidence tidak ditemukan di baris log: (); /bin/sleep 
- `srbh-3f285081547c2da3` putaran 2 (klasifikasi ke-2): lolos; alasan: 
  - riwayat label klasifikasi: CMD_INJECTION -> CMD_INJECTION; label akhir CMD_INJECTION (klasifikasi ke-2), status ok, benar CMD_INJECTION
