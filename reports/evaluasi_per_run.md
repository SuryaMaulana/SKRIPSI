Evaluasi evaluate-20261008T033140Z-ee70404 (commit ee70404, dirty=False)

Sumber label: data/processed/test_sample_500.jsonl. Prediksi di luar 6 kelas dihitung salah.

Tabel 4.2 — deteksi biner (serangan vs NORMAL)

| metode | cakupan | accuracy | precision | recall | F1 | FPR |
|---|---|---|---|---|---|---|
| agent_r1 | 500/500 | 0,836 | 0,991 | 0,808 | 0,890 | 0,034 |
| agent_r2 | 500/500 | 0,836 | 0,985 | 0,813 | 0,891 | 0,057 |
| agent_r3 | 500/500 | 0,838 | 0,991 | 0,811 | 0,892 | 0,034 |
| llm_single_r1 | 500/500 | 0,902 | 0,992 | 0,888 | 0,937 | 0,034 |
| llm_single_r2 | 500/500 | 0,898 | 0,992 | 0,883 | 0,935 | 0,034 |
| llm_single_r3 | 500/500 | 0,906 | 0,995 | 0,891 | 0,940 | 0,023 |
| regex | 500/500 | 0,704 | 1,000 | 0,641 | 0,781 | 0,000 |
| regex_full (post hoc) | 500/500 | 0,836 | 1,000 | 0,801 | 0,889 | 0,000 |

Tabel 4.3 — klasifikasi 6 kelas

| metode | cakupan | accuracy | macro-P | macro-R | macro-F1 | IK 95% macro-F1 |
|---|---|---|---|---|---|---|
| agent_r1 | 500/500 | 0,750 | 0,857 | 0,766 | 0,751 | [0,642; 0,818] |
| agent_r2 | 500/500 | 0,740 | 0,850 | 0,756 | 0,745 | [0,638; 0,810] |
| agent_r3 | 500/500 | 0,752 | 0,853 | 0,768 | 0,753 | [0,651; 0,817] |
| llm_single_r1 | 500/500 | 0,832 | 0,859 | 0,843 | 0,832 | [0,754; 0,881] |
| llm_single_r2 | 500/500 | 0,828 | 0,862 | 0,839 | 0,828 | [0,748; 0,878] |
| llm_single_r3 | 500/500 | 0,832 | 0,859 | 0,843 | 0,830 | [0,750; 0,878] |
| regex | 500/500 | 0,698 | 0,889 | 0,717 | 0,717 | [0,622; 0,779] |
| regex_full (post hoc) | 500/500 | 0,828 | 0,912 | 0,839 | 0,820 | [0,752; 0,859] |

F1 per kelas

| metode | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| agent_r1 | 0,983 | 0,991 | 0,706 | 0,772 | 0,367 | 0,688 |
| agent_r2 | 0,960 | 0,991 | 0,696 | 0,746 | 0,396 | 0,678 |
| agent_r3 | 0,971 | 0,991 | 0,697 | 0,797 | 0,382 | 0,680 |
| llm_single_r1 | 0,972 | 0,949 | 0,854 | 0,844 | 0,594 | 0,776 |
| llm_single_r2 | 0,967 | 0,957 | 0,835 | 0,844 | 0,597 | 0,769 |
| llm_single_r3 | 0,961 | 0,949 | 0,860 | 0,844 | 0,578 | 0,785 |
| regex | 0,367 | 1,000 | 0,894 | 0,898 | 0,598 | 0,543 |
| regex_full (post hoc) | 0,367 | 1,000 | 0,894 | 0,983 | 0,994 | 0,682 |

Tabel 4.5 — evidence literal (item evidence yang ada harfiah di raw_log_masked mentah/hasil decode)

| metode | baris | baris ber-evidence | item | item literal | proporsi literal | baris semua literal |
|---|---|---|---|---|---|---|
| agent_r1 | 493 | 493 | 726 | 654 | 0,901 | 428 |
| agent_r2 | 493 | 493 | 738 | 665 | 0,901 | 428 |
| agent_r3 | 497 | 497 | 727 | 647 | 0,890 | 421 |
| llm_single_r1 | 500 | 500 | 801 | 601 | 0,750 | 331 |
| llm_single_r2 | 500 | 500 | 799 | 614 | 0,768 | 339 |
| llm_single_r3 | 500 | 500 | 801 | 615 | 0,768 | 345 |
Metode tanpa field evidence (mis. regex) tidak dimasukkan.

Confusion matrix — agent_r1

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | tidak valid |
|---|---|---|---|---|---|---|---|
| SQLI | 86 | 0 | 0 | 0 | 0 | 3 | 0 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 0 | 0 | 17 | 0 |
| CMD_INJECTION | 0 | 0 | 30 | 56 | 0 | 0 | 3 |
| WEB_SCANNING | 0 | 0 | 13 | 0 | 20 | 54 | 2 |
| NORMAL | 0 | 1 | 0 | 0 | 0 | 85 | 2 |

Confusion matrix — agent_r2

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | tidak valid |
|---|---|---|---|---|---|---|---|
| SQLI | 84 | 0 | 1 | 0 | 0 | 3 | 1 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 0 | 0 | 17 | 0 |
| CMD_INJECTION | 2 | 0 | 32 | 53 | 0 | 0 | 2 |
| WEB_SCANNING | 0 | 0 | 13 | 0 | 22 | 54 | 0 |
| NORMAL | 0 | 1 | 0 | 0 | 0 | 83 | 4 |

Confusion matrix — agent_r3

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | tidak valid |
|---|---|---|---|---|---|---|---|
| SQLI | 85 | 0 | 0 | 0 | 0 | 4 | 0 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 70 | 0 | 0 | 19 | 0 |
| CMD_INJECTION | 1 | 0 | 29 | 59 | 0 | 0 | 0 |
| WEB_SCANNING | 0 | 0 | 13 | 0 | 21 | 54 | 1 |
| NORMAL | 0 | 1 | 0 | 0 | 0 | 85 | 2 |

Confusion matrix — llm_single_r1

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 87 | 1 | 0 | 0 | 0 | 1 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 82 | 0 | 2 | 5 |
| CMD_INJECTION | 3 | 1 | 13 | 65 | 6 | 1 |
| WEB_SCANNING | 0 | 1 | 8 | 0 | 41 | 39 |
| NORMAL | 0 | 3 | 0 | 0 | 0 | 85 |

Confusion matrix — llm_single_r2

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 87 | 1 | 0 | 0 | 0 | 1 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 81 | 0 | 2 | 6 |
| CMD_INJECTION | 4 | 0 | 15 | 65 | 3 | 2 |
| WEB_SCANNING | 0 | 1 | 9 | 0 | 40 | 39 |
| NORMAL | 0 | 3 | 0 | 0 | 0 | 85 |

Confusion matrix — llm_single_r3

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 87 | 1 | 0 | 0 | 0 | 1 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 1 | 83 | 0 | 2 | 3 |
| CMD_INJECTION | 5 | 0 | 13 | 65 | 5 | 1 |
| WEB_SCANNING | 0 | 2 | 8 | 0 | 39 | 40 |
| NORMAL | 0 | 2 | 0 | 0 | 0 | 86 |

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
