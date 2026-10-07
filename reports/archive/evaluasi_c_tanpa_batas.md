Evaluasi evaluate-20261007T164624Z-2efbd87 (commit 2efbd87, dirty=False)

Sumber label: data/processed/test_sample_500.jsonl. Prediksi di luar 6 kelas dihitung salah.

Tabel 4.2 — deteksi biner (serangan vs NORMAL)

| metode | cakupan | accuracy | precision | recall | F1 | FPR |
|---|---|---|---|---|---|---|
| llm_single | 500/500 | 0,906 | 0,992 | 0,893 | 0,940 | 0,034 |
| regex | 500/500 | 0,704 | 1,000 | 0,641 | 0,781 | 0,000 |
| regex_full (post hoc) | 500/500 | 0,836 | 1,000 | 0,801 | 0,889 | 0,000 |

Tabel 4.3 — klasifikasi 6 kelas

| metode | cakupan | accuracy | macro-P | macro-R | macro-F1 | IK 95% macro-F1 |
|---|---|---|---|---|---|---|
| llm_single | 500/500 | 0,830 | 0,858 | 0,841 | 0,829 | [0,751; 0,878] |
| regex | 500/500 | 0,698 | 0,889 | 0,717 | 0,717 | [0,622; 0,779] |
| regex_full (post hoc) | 500/500 | 0,828 | 0,912 | 0,839 | 0,820 | [0,752; 0,859] |

F1 per kelas

| metode | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| llm_single | 0,961 | 0,949 | 0,851 | 0,837 | 0,588 | 0,787 |
| regex | 0,367 | 1,000 | 0,894 | 0,898 | 0,598 | 0,543 |
| regex_full (post hoc) | 0,367 | 1,000 | 0,894 | 0,983 | 0,994 | 0,682 |

Tabel 4.5 — evidence literal (item evidence yang ada harfiah di raw_log_masked mentah/hasil decode)

| metode | baris | baris ber-evidence | item | item literal | proporsi literal | baris semua literal |
|---|---|---|---|---|---|---|
| llm_single | 499 | 499 | 785 | 588 | 0,749 | 336 |
Metode tanpa field evidence (mis. regex) tidak dimasukkan.

Confusion matrix — llm_single

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | tidak valid |
|---|---|---|---|---|---|---|---|
| SQLI | 87 | 1 | 0 | 0 | 0 | 1 | 0 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 83 | 0 | 2 | 4 | 0 |
| CMD_INJECTION | 5 | 1 | 13 | 64 | 5 | 1 | 0 |
| WEB_SCANNING | 0 | 1 | 10 | 0 | 40 | 37 | 1 |
| NORMAL | 0 | 3 | 0 | 0 | 0 | 85 | 0 |

Confusion matrix — regex

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 20 | 0 | 0 | 2 | 0 | 67 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 1 | 0 | 16 |
| CMD_INJECTION | 0 | 0 | 0 | 75 | 0 | 14 |
| WEB_SCANNING | 0 | 0 | 0 | 0 | 38 | 51 |
| NORMAL | 0 | 0 | 0 | 0 | 0 | 88 |

Confusion matrix — regex_full (post hoc)

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 20 | 0 | 0 | 2 | 0 | 67 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 1 | 1 | 15 |
| CMD_INJECTION | 0 | 0 | 0 | 89 | 0 | 0 |
| WEB_SCANNING | 0 | 0 | 0 | 0 | 89 | 0 |
| NORMAL | 0 | 0 | 0 | 0 | 0 | 88 |

Aturan pendorong salah kelas — regex

| aturan | baris salah | pasangan benar->prediksi |
|---|---|---|
| 932130 | 2 | SQLI->CMD_INJECTION: 2 |
| 932160 | 1 | PATH_TRAVERSAL->CMD_INJECTION: 1 |

Aturan pendorong salah kelas — regex_full (post hoc)

| aturan | baris salah | pasangan benar->prediksi |
|---|---|---|
| 932130 | 2 | SQLI->CMD_INJECTION: 2 |
| 920440 | 1 | PATH_TRAVERSAL->WEB_SCANNING: 1 |
| 932160 | 1 | PATH_TRAVERSAL->CMD_INJECTION: 1 |
