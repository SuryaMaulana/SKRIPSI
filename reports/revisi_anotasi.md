# Audit manusia — hasil anotasi

Berkas: A1 = audit/terisi/anotasi_A_anotator1.xlsx, A2 = audit/terisi/anotasi_A_anotator2.xlsx, B1 = audit/terisi/anotasi_B_anotator1.xlsx, B2 = audit/terisi/anotasi_B_anotator2.xlsx

## Fase A — label kelas (100 baris)

- Kesepakatan mentah antar anotator: 92.0% (92 dari 100 baris); Cohen's κ antar anotator (tak berbobot): 0.904.
- Anotator 1 vs label gerbang bukti: κ 0.964, kesepakatan mentah 97.0%. Anotator 2 vs label gerbang: κ 0.904, kesepakatan mentah 92.0%.
- Perlu diskusi (anotator tidak setuju): 8 baris.
- Konsensus berbeda dari label gerbang: 1 baris.
- Baris dengan catatan RAGU (kolom catatan berawalan RAGU): anotator 1 0, anotator 2 0.

Baris yang perlu diskusi (label gerbang sengaja tidak ditampilkan):

| id | anotator 1 | anotator 2 |
|---|---|---|
| srbh-76d0ab9d7a09264f | PATH_TRAVERSAL | WEB_SCANNING |
| srbh-1bb98d10fd188122 | CMD_INJECTION | WEB_SCANNING |
| srbh-2f98bdb3957467c5 | PATH_TRAVERSAL | WEB_SCANNING |
| srbh-5634e53daf68cb58 | PATH_TRAVERSAL | WEB_SCANNING |
| srbh-aa6f521ddcd8548c | CMD_INJECTION | WEB_SCANNING |
| srbh-3867d4a93c0e2198 | SQLI | CMD_INJECTION |
| srbh-b90bd4ea89d4b716 | NORMAL | WEB_SCANNING |
| srbh-adb08421bbbbd8ef | NORMAL | WEB_SCANNING |

Ringkasan per kelas (gerbang -> konsensus): NORMAL -> WEB_SCANNING: 1. Rincian per id di results/revisi_anotasi_per_baris.json.

Matriks konfusi konsensus vs label gerbang (baris = label gerbang, kolom = konsensus kedua anotator; "perlu diskusi" = kedua anotator berbeda):

| gerbang / konsensus | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | perlu diskusi | total |
|---|---|---|---|---|---|---|---|---|
| SQLI | 17 | 0 | 0 | 0 | 0 | 0 | 0 | 17 |
| XSS | 0 | 17 | 0 | 0 | 0 | 0 | 0 | 17 |
| PATH_TRAVERSAL | 0 | 0 | 13 | 0 | 0 | 0 | 4 | 17 |
| CMD_INJECTION | 0 | 0 | 0 | 15 | 0 | 0 | 2 | 17 |
| WEB_SCANNING | 0 | 0 | 0 | 0 | 16 | 0 | 0 | 16 |
| NORMAL | 0 | 0 | 0 | 0 | 1 | 13 | 2 | 16 |
| total | 17 | 17 | 13 | 15 | 17 | 13 | 8 | 100 |

## Fase B — relevansi bukti (skala 0–2)

- Butir unik: 277; κ berbobot kuadratik antar anotator: 0.498.
- Kesepakatan mentah antar anotator: 80.1% (222 dari 277 butir); dari 55 butir yang berbeda, 35 berselisih 1 dan 20 berselisih 2.
- Run: LLM tunggal = llm_single_r1; deep agent = agent_r1.

Per metode:

| metode | item | baris | rerata (2 anotator) | rerata anotator 1 | rerata anotator 2 | skor 0/1/2 anotator 1 | skor 0/1/2 anotator 2 | rerata, label benar (item) | rerata, label salah (item) |
|---|---|---|---|---|---|---|---|---|---|
| LLM tunggal | 157 | 100 | 1.61 | 1.72 | 1.50 | 15/14/128 | 25/29/103 | 1.67 (127) | 1.35 (30) |
| deep agent | 155 | 100 | 1.75 | 1.85 | 1.65 | 2/19/134 | 9/36/110 | 1.89 (119) | 1.31 (36) |

Per metode dan label prediksi:

| metode | label_prediksi | item | baris | rerata (2 anotator) | rerata anotator 1 | rerata anotator 2 | skor 0/1/2 anotator 1 | skor 0/1/2 anotator 2 |
|---|---|---|---|---|---|---|---|---|
| LLM tunggal | SQLI | 32 | 18 | 1.64 | 1.81 | 1.47 | 1/4/27 | 4/9/19 |
| LLM tunggal | XSS | 21 | 17 | 1.90 | 2.00 | 1.81 | 0/0/21 | 2/0/19 |
| LLM tunggal | PATH_TRAVERSAL | 25 | 20 | 1.46 | 1.68 | 1.24 | 4/0/21 | 9/1/15 |
| LLM tunggal | CMD_INJECTION | 15 | 13 | 1.83 | 2.00 | 1.67 | 0/0/15 | 0/5/10 |
| LLM tunggal | WEB_SCANNING | 10 | 7 | 0.85 | 1.00 | 0.70 | 4/2/4 | 6/1/3 |
| LLM tunggal | NORMAL | 54 | 25 | 1.62 | 1.63 | 1.61 | 6/8/40 | 4/13/37 |
| deep agent | SQLI | 21 | 17 | 1.86 | 1.95 | 1.76 | 0/1/20 | 2/1/18 |
| deep agent | XSS | 35 | 17 | 1.87 | 2.00 | 1.74 | 0/0/35 | 0/9/26 |
| deep agent | PATH_TRAVERSAL | 36 | 22 | 1.85 | 1.97 | 1.72 | 0/1/35 | 2/6/28 |
| deep agent | CMD_INJECTION | 16 | 10 | 1.97 | 2.00 | 1.94 | 0/0/16 | 0/1/15 |
| deep agent | WEB_SCANNING | 4 | 4 | 2.00 | 2.00 | 2.00 | 0/0/4 | 0/0/4 |
| deep agent | NORMAL | 43 | 30 | 1.42 | 1.51 | 1.33 | 2/17/24 | 5/19/19 |

Tabel silang skor per butir (baris = anotator 1, kolom = anotator 2):

| anotator 1 / anotator 2 | 0 | 1 | 2 | total |
|---|---|---|---|---|
| 0 | 13 | 1 | 2 | 16 |
| 1 | 2 | 27 | 1 | 30 |
| 2 | 18 | 31 | 182 | 231 |
| total | 33 | 59 | 185 | 277 |

Selisih rerata skor relevansi deep agent − LLM tunggal, IK 95% bootstrap klaster per baris log (100 baris, 10000 draw, default_rng(42), draw yang sama untuk semua sel; IK = persentil 2,5/97,5; p = 2 × porsi terkecil draw dengan selisih ≤ 0 atau ≥ 0). Per item = rerata atas item evidence seperti tabel per metode; per baris log = rerata atas baris dari selisih rerata skor kedua metode pada baris yang sama, setiap baris berbobot sama (100 baris memiliki item dari kedua metode):

| skor | per item: selisih | IK 95% | p | per baris log: selisih | IK 95% | p |
|---|---|---|---|---|---|---|
| rata-rata dua anotator | 0.143 | [0.043; 0.248] | 0.004 | 0.093 | [-0.012; 0.203] | 0.084 |
| anotator 1 | 0.132 | [0.040; 0.231] | 0.007 | 0.058 | [-0.028; 0.152] | 0.197 |
| anotator 2 | 0.155 | [0.015; 0.298] | 0.032 | 0.129 | [-0.027; 0.291] | 0.106 |

Item = kemunculan item evidence pada keluaran metode; item yang identik di kedua metode dinilai sekali dan dihitung untuk keduanya, dan item yang muncul dua kali pada keluaran yang sama dihitung dua kali. Rerata (2 anotator) = rerata atas item dari skor rata-rata kedua anotator. Skor 0/1/2 = jumlah item per skor. Label benar/salah menurut label gerbang bukti.
