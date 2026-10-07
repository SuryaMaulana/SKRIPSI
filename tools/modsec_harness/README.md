# Harness C ModSecurity 2.9.15 (sumber vektor emas)

Harness ini menjalankan fungsi C asli ModSecurity v2.9.15 (tag v2.9.15, commit
151074aca78a416764b12ba1221e61a17a6c714d) untuk menghasilkan `tests/fixtures/modsec_v2915_golden.json`. Vektor itu
dipakai `tests/baselines/test_modsec_golden.py` untuk memastikan port Python di `src/baselines/modsec.py` sama persis
dengan kode C (transformasi, peta Unicode 20127, dan pencocok frasa Aho-Corasick `@pm`/`@pmFromFile`).

| berkas | asal |
|---|---|
| `acmp.c`, `acmp.h` | salinan apa adanya dari `apache2/` ModSecurity v2.9.15 (byte-identik dengan tag) |
| `tfns_body_map.c` | 26 fungsi transformasi dari `apache2/re_tfns.c` dan `msc_util.c` v2.9.15 (token-identik), didahului stub APR minimal yang ditulis peninjau |
| `main_map.c` | ditulis peninjau: memuat `unicode.mapping` (re-implementasi `unicode_map_init` di `msc_unicode.c`) lalu menjalankan rantai transformasi in-place seperti `re.c` |
| `pm_main.c` | ditulis peninjau: automaton acmp dari argumen `@pm` atau berkas `@pmFromFile` (penanganan baris seperti `msre_op_pmFromFile_param_init`, tanpa `parse_pm_content`; untuk berkas `.data` CRS 4.30.0 hasilnya sama, diuji di `tests/baselines/test_crs_parser.py`) |
| `apr_stub/` | stub header APR minimal yang ditulis peninjau |
| `LICENSE-ModSecurity`, `NOTICE-ModSecurity` | lisensi Apache 2.0 dan NOTICE ModSecurity dari commit yang sama |

Kode ModSecurity berlisensi Apache License 2.0; lihat `LICENSE-ModSecurity` dan `NOTICE-ModSecurity`.

## Membangun dan memeriksa

```bash
make golden-check   # bangun harness di folder sementara, regenerasi vektor, bandingkan dengan fixture yang ada
```

Secara manual (dari folder ini):

```bash
cc -O2 -w -I apr_stub -o tfns_map main_map.c
cc -O2 -w -I apr_stub -o pm pm_main.c acmp.c
../../.venv/bin/python ../../scripts/make_modsec_golden.py --check .   # dari akar proyek: scripts/make_modsec_golden.py --check DIR
```

Hash biner bergantung pada kompilator dan platform (fixture dibuat dengan Apple clang 17 di macOS arm64). Yang diaudit
adalah isi vektornya; `meta.harness_sha256` di fixture hanya mencatat biner yang dipakai saat pembuatan.
