"""Langkah 10 — reports/data_report.md: statistik setiap tahap dan daftar keputusan praproses.

Laporan disusun dari statistik yang dikumpulkan `prepare.py` sehingga selalu sesuai dengan data yang dihasilkan.
Tidak memuat stempel waktu pembuatan agar keluaran identik antar-run.
"""

from __future__ import annotations

import pandas as pd

from .audit import SCAN_END
from .config import CLASSES, RANDOM_STATE, SRBH_DOI, SRBH_MD5
from .labels import EXCLUDED
from .normalize import KEYWORDS, LONG_NUMBER_DIGITS, MAX_DECODE_LAYERS
from .reporting import fmt_dec, fmt_int, mask_ips, md_table, pct
from .session import WINDOW_SECONDS

SPLITS = ("train", "val", "test")
FIREFOX70 = "Firefox/70.0"

# Keputusan penulis (disetujui pada titik berhenti Langkah 3 dan sesudahnya).
AUTHOR_DECISIONS = [
    ("Enam kelas target dan SR-BH 2020 sebagai dataset utama", "rancangan skripsi"),
    ("K1: gerbang bukti dua kunci; pola gerbang tidak sama dengan regex pembanding §3.5 skripsi; eksklusi dilaporkan per label", "§3"),
    ("K2a: 118.793 baris NORMAL bermasalah dikeluarkan dengan kode alasan", "§3"),
    ("K3b: XSS hanya dari label; kuota XSS di sampel ±57; aturan split sama untuk semua kelas", "§5, §6"),
    ("D4–D8: payload bertentangan dengan label dikeluarkan; PHP-CGI berlabel 88 → CMD; 194 → PT; probe penemuan → "
     "WEB_SCANNING; probe di luar taksonomi dikeluarkan", "§3"),
    ("D9: SQLI berbukti lemah ditandai `weak_evidence` dan tidak dimasukkan ke sampel uji (`sample_weak_sqli = exclude`)", "§3, §6"),
    ("Baris PT dari label 194: setelah dedup maksimal 200 baris per templat payload", "§4"),
    ("Urutan prioritas multi-label CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING", "§3"),
    ("Offset zona waktu di raw_log menjadi +0000; stempel waktu asli di kolom terpisah yang tidak dipakai metode", "§7"),
    ("Split stratified biasa tanpa grup per IP", "§5"),
    ("Fitur sesi (jendela 60 detik tanpa IP) tidak dipakai metode mana pun; klasifikasi murni per baris. Kolomnya tetap "
     "di parquet untuk analisis, tidak dimasukkan ke test_sample_500.jsonl", "§10"),
    ("Sampel NORMAL: maksimal 5 baris per templat (method, path tanpa query), baris ber-query diutamakan secara "
     "proporsional, lalu diambil 88", "§6"),
    ("Dedup isi sebelum split: kunci = raw_log tanpa stempel waktu dan tanpa protokol (`raw_log_masked`); baris pertama "
     "dipertahankan", "§2, §5"),
    ("`raw_log_masked`: [%t] → [01/Jan/2020:00:00:00 +0000] dan protokol → HTTP/1.1. Semua metode (regex, LLM tunggal, deep "
     "agent) hanya menerima raw_log_masked dan kolom hasil parsing tanpa time/timestamp/protocol; raw_log asli tetap di parquet", "§6, §7"),
    ("Evaluasi nanti: bootstrap klaster 1.000× per templat payload dengan kunci templat §6; kunci disimpan di kolom "
     "`template_key` test_sample_500", "§6"),
    ("Few-shot: calon contoh dari train yang isinya (tanpa stempel waktu) muncul di srbh_test dikeluarkan dari pool "
     "(kolom `fewshot_eligible` di srbh_train)", "§5"),
]

# Keputusan yang diambil asisten tanpa instruksi eksplisit (wajib tercatat).
OWN_DECISIONS = [
    ("Dataset diunduh dari Harvard Dataverse (v1.2, berkas tunggal data_capec_multilabel.csv) karena data/raw/ belum ada; "
     "MD5 diverifikasi setiap kali pipeline berjalan; data/raw/ tidak pernah ditulis ulang", "kesahihan sumber"),
    ("Sumber kebenaran pemetaan di configs/label_mapping.yaml (ikut versi kode); data/processed/label_mapping.yaml = salinan "
     "+ blok hitungan hasil run", "data/ dikecualikan dari git"),
    ("Kolom label dikenali dari isinya (hanya 0/1), bukan dari nama", "permintaan inspeksi tanpa asumsi nama kolom"),
    ("Semua 907.815 baris dipakai (publikasi menyebut 907.814); 2 baris kosong total dikeluarkan sebagai EMPTY_ROW", "tidak membuang diam-diam"),
    ("Aturan gerbang dipindahkan dari analisis bukti ke src/data/gate/ dengan paritas per baris terhadap angka yang disetujui; "
     "pola ditulis dari templat payload SR-BH dan alternatif yang tidak pernah cocok dibuang; CRS hanya rujukan diagnosis di "
     "analisis bukti, dan satu-satunya daftar turunan CRS yang dipakai adalah ekstensi aturan P1 (920440); pipeline berhenti "
     "dengan galat bila jumlah per aturan tidak sama dengan rows_expected", "syarat K1, §3"),
    ("Rekonstruksi: %l dan %u = '-' (tidak ada di dataset); %h = src_ip; %b = response_content_length, '-' bila kosong, 0, "
     "atau metode HEAD; Referer/UA kosong = '-'; request line memakai URI mentah yang masih ter-encode dan protokol "
     "request_http_protocol apa adanya (templat spesifikasi menulis HTTP/1.1; HTTP/1.0 hanya muncul di baris serangan, "
     "§7); kutip/backslash/karakter kontrol di-escape seperti Apache", "Langkah 4"),
    ("'+0000' diterapkan dengan mengganti teks offset; jam dinding asli dipertahankan. Offset SR-BH berganti "
     "(+0100 → +0200 → +0100) sementara jam dinding berjalan terus, sehingga konversi per-offset akan menciptakan "
     "tumpang-tindih 1 jam (17 Jul) dan celah 1 jam (19 Jul) palsu. Implementasi awal (konversi UTC) diganti setelah review", "§7"),
    ("Parser: baris gagal urai ditandai `parse_error` (format/time/request), tidak dibuang; request line dicocokkan selagi "
     "masih ter-escape; path dan query dipisah pada '?' pertama", "Langkah 5"),
    (f"Normalisasi: maksimal {MAX_DECODE_LAYERS} lapis URL-decode; '+'→spasi hanya pada lapis pertama query; entity HTML "
     "numerik dan entity bernama yang diakhiri ';' didekode (tanpa ';' dibiarkan agar parameter seperti &copy= tidak rusak); "
     f"karakter kontrol ditulis sebagai teks \\xhh; hanya {len(KEYWORDS)} kata kunci (SQL, HTML/JS, shell, skema URL) yang "
     f"dijadikan huruf kecil; UUID dan angka ≥{LONG_NUMBER_DIGITS} digit yang tidak menempel huruf → <*>; Referer tidak "
     "dinormalisasi (tidak diminta)", "Langkah 6"),
    (f"Jendela sesi = semua permintaan dengan detik dalam [t−{WINDOW_SECONDS - 1}, t] (termasuk permintaan lain pada detik "
     "yang sama); dihitung atas seluruh aliran log terurai, termasuk baris yang nanti dikeluarkan/duplikat; 4xx = status "
     "400–499; path unik memakai path mentah", "Langkah 7 (kolom analisis saja)"),
    ("Pada dedup isi, isi identik yang berlabel berbeda dibuang semua salinannya (jumlahnya dilaporkan di §2). Dedup awal "
     "memakai raw_log utuh (termasuk stempel waktu) dan diganti dedup isi atas keputusan penulis", "Langkah 8"),
    ("Templat RFI = skema seperti tertulis + host[:port] + path (kata pencarian 'OWASP …' disamakan); pemilihan 200 baris "
     f"acak dengan random_state={RANDOM_STATE}; baris yang terpotong disimpan di srbh_excluded.parquet (RFI_TEMPLATE_CAP)", "D6"),
    (f"Split: train_test_split 30% lalu 50/50, stratified per kelas, random_state={RANDOM_STATE}", "Langkah 8"),
    ("Sampel 500: seluruh XSS di split uji; sisa kuota dibagi rata ke lima kelas lain (kelebihan menurut urutan kelas); "
     f"setiap pengambilan acak per kelas dan per templat NORMAL memakai random_state={RANDOM_STATE}", "K3b"),
    ("Tafsiran 'utamakan baris ber-query secara proporsional' (keputusan penulis #12): di setiap templat NORMAL, slot "
     "(maks. 5) dibagi proporsional antara baris ber-query dan tanpa query lalu dibulatkan ke atas untuk baris ber-query; "
     "bila salah satu jenis kurang, slot diisi jenis lain; 88 baris lalu diambil acak dari pool hasil batas. Templat = "
     "(method, path mentah tanpa query). Hanya 10 templat di pool uji yang mencampur kedua jenis baris", "§6"),
    ("test_sample_500.jsonl = id + kolom evaluasi (label, template_key; tidak boleh diberikan ke metode) + masukan metode "
     "(raw_log_masked, hasil parsing tanpa time/timestamp/protocol, serta path_norm/query_norm/ua_norm). Kolom normalisasi "
     "diikutkan sebagai bagian 'kolom hasil parsing' karena diturunkan dari path/query/UA dan tidak memuat waktu atau protokol. "
     "raw_log asli, metadata label, dan fitur sesi hanya di parquet. Baris ditulis dalam urutan acak "
     f"(random_state={RANDOM_STATE}) karena urutan row_id = urutan waktu, yang mengelompokkan kelas", "mencegah kebocoran"),
    ("id = 'srbh-' + 16 heksa pertama SHA-256(\"srbh2020:<row_id>\"): stabil tetapi tidak membocorkan urutan berkas; row_id "
     "(posisi baris di CSV mentah) tetap di parquet untuk penelusuran", "mencegah kebocoran"),
    ("Byte NUL hasil decode tidak pernah dipakai sebagai kunci hash pandas (kunci memakai teks mentah yang bebas NUL)", "bug yang ditemukan saat analisis"),
    ("Sel tabel laporan meng-escape \\ | & < agar HTML mentah dari payload (mis. <script>) tidak ditafsirkan penampil Markdown", "keterbacaan"),
]


def _class_table(counts: dict[str, dict[str, int]]) -> str:
    rows = []
    for cls in CLASSES:
        row = [cls]
        for split in SPLITS:
            n, total = counts[split].get(cls, 0), sum(counts[split].values())
            row.append(f"{fmt_int(n)} ({pct(n, total)})")
        rows.append(row)
    rows.append(["**total**"] + [fmt_int(sum(counts[s].values())) for s in SPLITS])
    return md_table(["kelas", "train", "val", "test"], rows)


def _per_label_table(summary: dict, targets: dict[str, str]) -> str:
    rows = []
    for label, info in summary["per_capec_label"].items():
        kept = ", ".join(f"{k} {fmt_int(v)}" for k, v in info["final_class"].items() if k != EXCLUDED) or "–"
        excluded = info["final_class"].get(EXCLUDED, 0)
        reasons = ", ".join(f"{k} {fmt_int(v)}" for k, v in info["excluded_by_reason"].items()) or "–"
        rows.append([label, targets.get(label, "NORMAL"), fmt_int(info["rows_with_label"]), kept, fmt_int(excluded), reasons])
    return md_table(["label", "target label sendiri", "baris berlabel", "kelas akhir baris-baris itu", "dikeluarkan",
                     "alasan akhir dikeluarkan"], rows, limit=400)


def _parity_table(parity: list[dict]) -> tuple[str, int]:
    rows = [[p["label"], p["rule_id"], fmt_int(p["expected"]), fmt_int(p["actual"]), "✓" if p["expected"] == p["actual"] else "✗"]
            for p in parity]
    mismatches = sum(p["expected"] != p["actual"] for p in parity)
    return md_table(["label", "aturan", "rows_expected (disetujui)", "aktual", "cocok"], rows), mismatches


def _leak_table(final: pd.DataFrame) -> str:
    rows = []
    for cls in CLASSES:
        part = final[final["label"] == cls]
        rows.append([
            cls, fmt_int(len(part)),
            pct(int((part["status"] == 404).sum()), len(part)),
            pct(int(((part["method"] == "GET") & (part["path"] == "/") & (part["query"] == "")).sum()), len(part)),
            pct(int((part["protocol"] == "HTTP/1.0").sum()), len(part)),
            pct(int(part["user_agent"].str.contains(FIREFOX70, regex=False).sum()), len(part)),
            f"{part['timestamp'].min():%d %b %Y} – {part['timestamp'].max():%d %b %Y}",
            f"{part['sess_req_60s'].median():.0f}",
            fmt_dec(part["sess_4xx_ratio_60s"].median()),
            f"{part['sess_uniq_paths_60s'].median():.0f}",
        ])
    return md_table(["kelas", "baris", "status 404", "`GET /`", "HTTP/1.0", "UA Firefox/70", "rentang tanggal",
                     "median req/60 dtk", "median rasio 4xx", "median path unik"], rows)


def _path_family(path: str) -> str:
    """Dua segmen pertama path, mis. /blog/wp-content/uploads/... -> /blog/wp-content."""
    parts = [p for p in path.split("/") if p][:2]
    return "/" + "/".join(parts) if parts else "/"


def _normal_sample_section(sample: pd.DataFrame, pools: dict, windows: dict) -> list[str]:
    normal = sample[sample["label"] == "NORMAL"]
    templates = normal.groupby(["method", "path"]).size().sort_values(ascending=False)
    family = normal.assign(family=normal["path"].map(_path_family)).groupby("family").agg(
        baris=("row_id", "size"), templat=("path", "nunique")).sort_values("baris", ascending=False)
    multi = templates[templates > 1]
    get_root = int(((normal["method"] == "GET") & (normal["path"] == "/") & (normal["query"] == "")).sum())
    in_scan = normal["timestamp"] < SCAN_END
    tool_ua = int((in_scan & normal["user_agent"].str.contains(FIREFOX70, regex=False)).sum())
    pool, capped = windows["pool"], windows["capped"]
    return [
        "### Sampel NORMAL",
        "",
        f"Pool NORMAL di split uji {fmt_int(pools['NORMAL_before_template_cap'])} baris → {fmt_int(pools['NORMAL'])} baris "
        f"setelah batas 5 per templat (method, path tanpa query) → {fmt_int(len(normal))} baris diambil acak "
        f"(random_state={RANDOM_STATE}). Sampel mewakili **{fmt_int(len(templates))} templat unik**; "
        f"{fmt_int(int((normal['query'] != '').sum()))} baris ber-query; {fmt_int(get_root)} baris `GET /`; "
        f"{fmt_int(int(in_scan.sum()))} baris bertanggal 17–19 Juli, hari ketika pemindai berjalan ({fmt_int(tool_ua)} di "
        "antaranya memakai UA Firefox/70 milik alat uji).",
        "",
        f"Penyebabnya batas templat: di pool NORMAL uji, {pct(pool['rows'] - pool['scan_rows'], pool['rows'])} baris "
        f"bertanggal 20 Juli–1 November, tetapi baris itu hanya memuat {fmt_int(pool['other_templates'])} templat (method, "
        f"path), sedangkan baris 17–19 Juli memuat {fmt_int(pool['scan_templates'])} templat. Porsi 17–19 Juli karena itu naik "
        f"dari {pct(pool['scan_rows'], pool['rows'])} pool menjadi {pct(capped['scan_rows'], capped['rows'])} pool setelah "
        "batas 5 per templat.",
        "",
        md_table(["method", "baris"], [[m, fmt_int(int(n))] for m, n in normal["method"].value_counts().items()]),
        "",
        "Distribusi menurut keluarga path (dua segmen pertama):",
        "",
        md_table(["keluarga path", "baris", "templat"], [[f, fmt_int(int(r.baris)), fmt_int(int(r.templat))] for f, r in family.iterrows()]),
        "",
        "Templat yang muncul lebih dari sekali: "
        + (", ".join(f"`{m} {p}` ({n})" for (m, p), n in multi.items()) or "tidak ada")
        + f"; {fmt_int(int((templates == 1).sum()))} templat lain masing-masing 1 baris.",
        "",
    ]


def _concentration_table(conc: pd.DataFrame) -> str:
    rows = [[r.kelas, fmt_int(r.baris), fmt_int(r.templat), r.terbesar, f"{fmt_int(r.terbesar_n)} ({pct(r.terbesar_n, r.baris, 0)})",
             pct(r.top3_n, r.baris, 0), fmt_dec(r.n_eff, 1)] for r in conc.itertuples()]
    return md_table(["kelas", "baris", "templat", "templat terbesar", "baris templat terbesar", "porsi 3 teratas",
                     "n efektif (Kish)"], rows, limit=70)


def _overlap_table(overlap: dict) -> str:
    rows = []
    for cls in [*CLASSES, "_total"]:
        cells = ["**total**" if cls == "_total" else cls]
        for split in ("val", "test", "sample"):
            twins, n = overlap[split][cls]
            cells.append(f"{fmt_int(twins)}/{fmt_int(n)} ({pct(twins, n, 1)})")
        rows.append(cells)
    return md_table(["kelas", "val: punya kembaran di train", "test: punya kembaran di train",
                     "sampel 500: punya kembaran di train"], rows)


def render(stats: dict, final: pd.DataFrame, sample: pd.DataFrame) -> str:
    st, lab = stats["stages"], stats["labels"]
    parity_md, parity_bad = _parity_table(stats["parity"])
    cap = stats["cap_table"]
    examples = []
    for cls in CLASSES:
        rows = sample[sample["label"] == cls]
        picked = rows.sample(n=min(3, len(rows)), random_state=RANDOM_STATE).sort_values("row_id")
        examples.append(f"**{cls}**\n\n```text\n" + "\n".join(mask_ips(x) for x in picked["raw_log_masked"]) + "\n```\n")
    rule_mix = (sample.groupby(["label", "label_rule"]).size().rename("baris").reset_index()
                .sort_values(["label", "baris"], ascending=[True, False]))
    ratio_4xx = final.groupby("label")["sess_4xx_ratio_60s"].median()
    other_days = final.loc[final["label"] == "NORMAL", "timestamp"] >= SCAN_END
    attack_4xx = ratio_4xx.drop("NORMAL")
    multi = stats["multi_candidates"]
    overlap = stats["content_overlap"]
    tp = stats["time_proxy"]
    sel = stats["selection_effect"]
    off = stats["offsets"]
    weak_test, sqli_test = stats["weak_sqli_test"]
    http10 = {c: n for c, n in stats["protocol_http10"].items() if n}
    time_acc = pct(round(tp["accuracy"] * 1000), 1000, 1)

    lines = [
        "# Laporan Data — SR-BH 2020 (Langkah 1–10)",
        "",
        "Dihasilkan otomatis oleh `make data` (`python -m src.data.prepare`). Alamat IPv4 pada contoh disamarkan (a.b.x.x).",
        "",
        "## 1. Sumber",
        "",
        f"- SR-BH 2020, Harvard Dataverse doi:{SRBH_DOI} (versi 1.2, CC0 1.0), berkas `data_capec_multilabel.csv`, MD5 `{SRBH_MD5}`.",
        f"- {fmt_int(stats['inspection']['rows'])} baris, {len(stats['inspection']['feature_columns'])} fitur + "
        f"{len(stats['inspection']['label_columns'])} kolom label (1 normal + 13 CAPEC). Inspeksi lengkap: `reports/srbh_inspection.md`.",
        "- Usulan dan bukti pemetaan label: `reports/label_mapping_proposal.md`; pemetaan yang dipakai: `configs/label_mapping.yaml`.",
        "",
        "## 2. Jumlah baris per tahap",
        "",
        md_table(["tahap", "baris"], [
            ["CSV mentah", fmt_int(st["raw"])],
            ["dikeluarkan oleh gerbang bukti (EXCLUDED)", fmt_int(st["excluded_by_gate"])],
            ["masuk dataset 6 kelas", fmt_int(st["six_class"])],
            ["dibuang: duplikat isi (`raw_log_masked`: tanpa waktu dan protokol)", fmt_int(stats["dedup"]["duplicates_dropped"])],
            ["dibuang: isi identik berlabel berbeda", fmt_int(stats["dedup"]["conflict_rows_dropped"])],
            ["setelah dedup", fmt_int(st["after_dedup"])],
            ["dibuang: batas 200 per templat RFI (label 194)", fmt_int(st["rfi_cap_dropped"])],
            ["setelah batas templat (masuk split)", fmt_int(st["after_cap"])],
            ["srbh_train / srbh_val / srbh_test", " / ".join(fmt_int(st[s]) for s in SPLITS)],
            ["test_sample_500", fmt_int(st["sample"])],
        ]),
        "",
        "Duplikat yang dibuang per kelas: "
        + (", ".join(f"{k} {fmt_int(v)}" for k, v in stats["dedup"]["duplicates_dropped_by_class"].items()) or "tidak ada") + ".",
        "",
        "Kunci dedup = `raw_log_masked` (stempel waktu dikonstankan dan protokol diseragamkan; keputusan penulis), sehingga "
        "permintaan yang sama pada detik berbeda hanya disimpan sekali, yaitu kemunculan pertamanya di berkas. "
        f"{fmt_int(overlap['rows'])} baris yang masuk split berisi {fmt_int(overlap['distinct_contents'])} isi berbeda "
        "(tanpa stempel waktu).",
        "",
        "## 3. Pemetaan label dan gerbang bukti",
        "",
        "Kelas akhir sebuah baris harus (1) berasal dari salah satu label SR-BH miliknya dan (2) buktinya terlihat di field "
        "Combined Log Format. Baris yang tidak memenuhi dikeluarkan dengan kode alasan dan disimpan di "
        "`data/processed/srbh_excluded.parquet`.",
        "",
        md_table(["kelas", "baris (sebelum dedup)"], [[k, fmt_int(v)] for k, v in lab["final_distribution"].items()]),
        "",
        "SQLI berbukti lemah (aturan S2: hanya probe metakarakter 1–2 karakter tanpa sintaks SQL, yaitu salah satu dari "
        f"' \" ( ) ; % | atau NULL, atau pasangan kutip '\" / \"'): {fmt_int(lab['weak_evidence_sqli'])} baris, ditandai "
        "`weak_evidence=True`.",
        "",
        "Multi-label: setiap label aktif menyumbang kandidat kelas, alasan eksklusi, atau tidak keduanya (netral). Bila ada "
        "beberapa kandidat, berlaku prioritas CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING; bila tidak ada "
        "kandidat, alasan dipilih dengan urutan LABEL_MISMATCH > OUT_OF_SCOPE > RFI_SCHEMELESS > HIDDEN_EVIDENCE > NO_EVIDENCE. "
        f"Hanya {fmt_int(sum(multi.values()))} baris yang punya lebih dari satu kandidat: "
        + ", ".join(f"{k.replace('+', ' vs ')} {fmt_int(v)}" for k, v in multi.items()) + ".",
        "",
        "### Jumlah dikeluarkan per label (syarat K1)",
        "",
        "Kolom \"kelas akhir\" dan \"alasan akhir\" menunjukkan hasil akhir baris, yang bisa ditentukan label lain pada baris "
        "yang sama. Contohnya label 33 dan 248 (target sendiri UNMAPPED) tetap tampak punya baris CMD_INJECTION/WEB_SCANNING "
        "karena label pendampingnya. Satu baris multi-label dihitung di setiap labelnya. Tabel paritas di bawah sebaliknya hanya "
        "menghitung aturan milik label itu sendiri, sehingga kedua tabel bisa berbeda tipis. Angka K2a (118.793) adalah "
        "N1+N2+N3; dua baris kosong (EMPTY_ROW) membuat total eksklusi label Normal menjadi 118.795.",
        "",
        _per_label_table(lab, stats["mapping_targets"]),
        "",
        "Total dikeluarkan per alasan: " + ", ".join(f"{k} {fmt_int(v)}" for k, v in lab["excluded_by_reason"].items()) + ".",
        "",
        "Arti kode alasan (dari `configs/label_mapping.yaml`):",
        "",
        md_table(["kode", "arti"], [[k, " ".join(str(v).split())] for k, v in stats["exclusion_reasons"].items()], limit=800),
        "",
        "### Independensi dan sirkularitas terhadap metode berbasis pola (§3.4–§3.5 skripsi)",
        "",
        "Asal-usul pola gerbang (`src/data/gate/`): pola ditulis dari templat payload yang teramati di SR-BH (analisis bukti "
        "2026-10-07), dan alternatif yang tidak pernah cocok di data dibuang. CRS menjadi rujukan diagnosis di analisis bukti, "
        "yaitu untuk memahami aturan mana yang memicu label (daftar restricted_extensions 920440, daftar UA pemindai 913, pola "
        "mirip 921xxx, semantik 930130). Satu-satunya daftar turunan CRS yang dipakai gerbang adalah daftar ekstensi aturan P1.",
        "",
        "Tumpang-tindih yang perlu dinyatakan sebelum baseline §3.5 (CRS 941/942/930/931/932/913 + aturan pemindaian Baş "
        "Seyyar dkk.) dibangun:",
        "",
        "- P1 (label 272): 11 ekstensi berkas cadangan/terlarang yang muncul di SR-BH, subset restricted_extensions CRS 920440. "
        "Kategori 920 tidak termasuk baseline, tetapi bila 920440 kelak ditambahkan, tumpang-tindih ini harus disebut.",
        "- W1 (label 310): UA \"Nmap Scripting Engine\" dan \"zgrab\". Polanya tidak disalin dari CRS, tetapi daftar UA kategori "
        "913 juga memuat keduanya, sehingga baris WEB_SCANNING dari label 310 terlihat oleh baseline secara konsep.",
        "- T1/T3 (label 126): keluarga berkas OS (etc/passwd, win.ini, boot.ini) dan berkas terlarang (.git, .svn, .htaccess, "
        "cadangan wp-config) adalah sasaran kategori 930 (LFI). Gerbang memetakan berkas terlarang tanpa traversal (T3) ke "
        "WEB_SCANNING, sedangkan semantik CRS 930130 menganggapnya LFI. Pemetaan kelas baseline untuk hit 930130 harus "
        "diputuskan dan dicatat sebelum penilaian, agar baseline tidak dinilai salah karena pilihan taksonomi.",
        "- V1/P1/T3/W1 (WEB_SCANNING) belum dibandingkan dengan aturan pemindaian Baş Seyyar dkk. karena baseline belum ada.",
        "",
        "Larangan impor/salin modul gerbang berlaku untuk baseline §3.5 **dan** untuk alat `pattern_match`/`lookup_owasp` "
        "sub-agen Analisis Payload deep agent (§3.4), karena keduanya juga diturunkan dari CRS.",
        "",
        "Sirkularitas yang tidak bisa dihilangkan: label SR-BH adalah keluaran CRS (ditinjau penulis dataset), sehingga komponen "
        "apa pun yang diturunkan dari CRS (baseline maupun alat agen) diuntungkan sejak awal. Selain itu, gerbang memilih baris "
        "serangan yang buktinya terlihat oleh pola dan membersihkan NORMAL dari pola payload/probe. Bila aturan pembersih NORMAL "
        "(N1–N3) dijalankan tanpa label pada sampel uji, aturan itu menandai "
        + ", ".join(f"{c} {fmt_int(int(r.ditandai))}/{fmt_int(int(r.baris))}" for c, r in sel.iterrows())
        + ". Untuk kelas yang hampir seluruhnya tertandai, pemisahan serangan vs normal pada data uji praktis sama dengan "
        "himpunan pola gerbang itu sendiri. Recall dan FPR komponen berbasis pola karena itu batas atas, dan ketahanan terhadap "
        "obfuscation di luar keluarga payload ini tidak teruji.",
        "",
        "### Paritas aturan terhadap angka yang disetujui",
        "",
        parity_md,
        "",
        ("Semua aturan cocok dengan angka yang disetujui. Pipeline berhenti dengan galat bila ada yang tidak cocok."
         if parity_bad == 0 else f"**{parity_bad} aturan tidak cocok** — lihat tabel."),
        "",
        "### Pembanding: target per label tanpa gerbang bukti",
        "",
        "Kelas = `target` per label di `configs/label_mapping.yaml` (termasuk 194→PATH_TRAVERSAL dan 272/274→WEB_SCANNING dari "
        "D6/D7; 248, 34, 33, 16, 153 UNMAPPED), prioritas penulis untuk multi-label, label NORMAL apa adanya, tanpa pemeriksaan "
        "bukti. Ini **bukan** Varian A di `reports/label_mapping_proposal.md` (pemetaan langsung per nama CAPEC: 194/272/274 "
        "UNMAPPED, 248→CMD_INJECTION), sehingga angka PATH_TRAVERSAL, WEB_SCANNING, CMD_INJECTION, dan EXCLUDED berbeda dari sana.",
        "",
        md_table(["kelas", "baris"], [[k, fmt_int(v)] for k, v in stats["labels_only"].items()]),
        "",
        "## 4. Batas templat RFI (label 194 → PATH_TRAVERSAL)",
        "",
        f"Setelah dedup, setiap templat payload RFI dibatasi maksimal {stats['rfi_cap']} baris (acak, random_state={RANDOM_STATE}).",
        "",
        md_table(["templat", "sebelum", "sesudah"], [[r["rfi_template"], fmt_int(r["before"]), fmt_int(r["after"])] for r in cap], limit=200),
        "",
        f"Total: {fmt_int(sum(r['before'] for r in cap))} → {fmt_int(sum(r['after'] for r in cap))} baris; "
        f"porsi label 194 di PATH_TRAVERSAL setelah batas: {pct(sum(r['after'] for r in cap), stats['pt_after_cap'])}.",
        "",
        "## 5. Distribusi kelas per split",
        "",
        _class_table(stats["splits"]),
        "",
        "Pemeriksaan kembaran isi (baris log tanpa stempel waktu) antara train dan bagian lain, per kelas. Karena dedup isi "
        "dilakukan sebelum split, semua angka harus 0:",
        "",
        _overlap_table(overlap),
        "",
        f"Pool few-shot (kolom `fewshot_eligible` di srbh_train): {fmt_int(stats['fewshot']['eligible'])} baris layak; "
        f"{fmt_int(stats['fewshot']['excluded'])} baris dikeluarkan karena isinya muncul di srbh_test.",
        "",
        "## 6. Sampel uji 500 baris (`test_sample_500.jsonl`)",
        "",
        "Kolom: `id`; kolom evaluasi `label` dan `template_key` (**tidak boleh diberikan ke metode**); masukan metode "
        "`raw_log_masked`, hasil parsing tanpa time/timestamp/protocol (`ip`, `ident`, `user`, `method`, `path`, `query`, "
        "`status`, `bytes`, `referer`, `user_agent`), dan hasil normalisasi (`path_norm`, `query_norm`, `ua_norm`). raw_log asli, "
        "waktu, protokol, metadata label, dan fitur sesi hanya ada di parquet. "
        f"Baris ditulis dalam urutan acak (random_state={RANDOM_STATE}); id bersifat opak (§11). Setiap pengambilan acak per "
        f"kelas memakai random_state={RANDOM_STATE}.",
        "",
        md_table(["kelas", "kuota (= baris di sampel)", "pool yang dipakai"],
                 [[c, fmt_int(stats["sample_quotas"][c]), fmt_int(stats["sample_pool"][c])] for c in CLASSES]),
        "",
        "Pool XSS = seluruh XSS di split uji; pool NORMAL = setelah batas templat. Pool SQLI mengikuti opsi "
        f"`sample_weak_sqli = {stats['weak_sqli']}`: split uji memuat {fmt_int(weak_test)} baris SQLI berbukti lemah dari "
        f"{fmt_int(sqli_test)} ({pct(weak_test, sqli_test, 1)}); sesuai keputusan penulis, baris itu tidak masuk sampel. "
        "Komposisi sampel menurut aturan penentu kelas:",
        "",
        md_table(["kelas", "aturan", "baris"], rule_mix.values.tolist()),
        "",
        *_normal_sample_section(sample, stats["sample_pool"], stats["normal_windows"]),
        "### Konsentrasi templat payload",
        "",
        "Baris dalam satu kelas tidak saling bebas: banyak yang berasal dari templat payload pemindai yang sama. Kunci templat "
        "per kelas (hanya untuk pelaporan): XSS = potongan payload + pembawanya; PATH_TRAVERSAL = templat RFI atau bentuk "
        "traversal; CMD_INJECTION = potongan perintah; WEB_SCANNING = aturan + metode/UA/ekstensi; SQLI = potongan payload "
        "dengan angka disamakan; NORMAL = method + path. n efektif Kish = n² / Σ m² (m = baris per templat).",
        "",
        _concentration_table(stats["concentration"]),
        "",
        "Evaluasi memakai bootstrap klaster 1.000× yang meresampel templat, bukan baris (keputusan penulis), karena bootstrap "
        "per baris akan terlalu sempit untuk kelas yang didominasi satu templat. Kunci templat tiap baris disimpan di kolom "
        "`template_key` test_sample_500.jsonl.",
        "",
        "### Waktu sebagai penanda kelas",
        "",
        "Pemindai menjalankan satu jenis serangan dalam satu waktu, sehingga waktu permintaan menyandikan kelas. Dengan menebak "
        "label mayoritas baris train pada menit yang sama, tanpa melihat isi permintaan, sampel uji terklasifikasi dengan akurasi "
        f"**{time_acc}** (Macro-F1 {fmt_dec(tp['macro_f1'])}). Distribusi tanggal per kelas di sampel:",
        "",
        md_table(["kelas", *tp["days"].columns], [[c, *[fmt_int(int(v)) for v in r]] for c, r in tp["days"].iterrows()]),
        "",
        "Karena itu metode hanya menerima `raw_log_masked` (waktu dikonstankan) dan kolom parsing tanpa time/timestamp/"
        "protocol (keputusan penulis); waktu asli hanya ada di parquet untuk analisis.",
        "",
        "## 7. Rekonstruksi log (Langkah 4)",
        "",
        "Format: `%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"`. Placeholder dan aturan penulisan ada di "
        "daftar keputusan (§11). Teks waktu asli disimpan di `timestamp_original`. `raw_log_masked` = raw_log dengan [%t] "
        "diganti `[01/Jan/2020:00:00:00 +0000]` dan protokol request line diganti `HTTP/1.1`; kolom inilah yang menjadi masukan "
        "metode dan kunci dedup.",
        "",
        "Waktu: offset di teks waktu diganti +0000 dan jam dinding dipertahankan. Rangkaian offset menurut urutan berkas:",
        "",
        md_table(["offset", "baris pertama", "baris terakhir", "jumlah"],
                 [[r["offset"], fmt_int(r["first_row"]), fmt_int(r["last_row"]), fmt_int(r["rows"])] for r in off["runs"]]),
        "",
        "Pada setiap pergantian, jam dinding berlanjut dengan langkah normal (mis. `18:59:58 +0100` → `19:00:13 +0200`). Jadi "
        "offset hanyalah label; konversi per-offset akan menciptakan tumpang-tindih 1 jam (17 Jul) dan celah 1 jam (19 Jul) palsu. "
        f"Blok bertanggal 01/Nov/2020 ({fmt_int(off['nov_rows'])} baris, baris {fmt_int(off['nov_first_row'])}–"
        f"{fmt_int(off['nov_last_row'])}): {fmt_int(off['nov_copies_of_first_rows'])} baris pertamanya identik (jam, URI, UA) "
        f"dengan baris 0–{fmt_int(off['nov_copies_of_first_rows'] - 1)}, hanya tanggalnya berbeda. Ini artefak pembuat dataset.",
        "",
        "Protokol: request line memakai `request_http_protocol` apa adanya. HTTP/1.0 hanya muncul di baris serangan dataset "
        "6 kelas (" + (", ".join(f"{c} {fmt_int(n)}" for c, n in http10.items()) or "tidak ada") + "; 0 di NORMAL), "
        "sehingga protokol diseragamkan di `raw_log_masked` dan kolom `protocol` tidak diberikan ke metode.",
        "",
        "## 8. Parsing (Langkah 5)",
        "",
        f"- Baris gagal diurai: **{fmt_int(stats['parse']['failed'])}** dari {fmt_int(st['raw'])} "
        f"({', '.join(f'{k}: {fmt_int(v)}' for k, v in stats['parse']['by_reason'].items()) or 'tidak ada'}); "
        f"row_id: {', '.join(str(r) for r in stats['parse']['failed_rows']) or '–'}."
        + (" Semuanya baris yang seluruh field-nya kosong (EMPTY_ROW)." if stats["parse"]["all_empty_rows"] else ""),
        f"- Gagal urai di dataset 6 kelas: {fmt_int(stats['parse']['failed_in_six_class'])}.",
        "- Field hasil urai dibandingkan dengan nilai asli CSV: metode, status, Referer, dan User-Agent identik untuk semua baris terurai.",
        "",
        "## 9. Normalisasi (Langkah 6)",
        "",
        "Kolom mentah `path`, `query`, `user_agent` dan versi ternormalisasinya `path_norm`, `query_norm`, `ua_norm` "
        "disimpan berdampingan. Aturannya ada di §11.",
        "",
        "## 10. Fitur sesi: artefak dataset, tidak dipakai metode",
        "",
        f"Kolom `sess_req_60s`, `sess_4xx_ratio_60s`, `sess_uniq_paths_60s` (jendela {WINDOW_SECONDS} detik, tanpa IP; resolusi "
        "stempel waktu 1 detik sudah cukup untuk jendela ini) dihitung dan disimpan di parquet untuk analisis, tetapi **tidak "
        "dipakai metode mana pun**: klasifikasi murni per baris (keputusan penulis).",
        "",
        "Alasannya adalah artefak dataset: median rasio status 4xx dalam jendela 60 detik adalah "
        f"**{fmt_dec(ratio_4xx['NORMAL'])} untuk NORMAL** tetapi **{fmt_dec(attack_4xx.min())}–{fmt_dec(attack_4xx.max())} untuk "
        "kelas serangan**. SR-BH hanya punya satu alamat IP dan seluruh serangan dikirim alat pemindai dalam jendela 17–19 Juli, "
        f"sedangkan {pct(int(other_days.sum()), len(other_days))} baris NORMAL bertanggal 20 Juli–1 November. Fitur jendela "
        "waktu karena itu "
        "mengukur kapan sebuah permintaan terjadi, bukan apakah isinya serangan, sehingga akan menggelembungkan kinerja secara "
        "semu. Tabel berikut (dataset 6 kelas setelah batas templat) juga memperlihatkan penanda kelas lain di luar payload: "
        "status 404, `GET /`, HTTP/1.0, UA Firefox/70 milik alat uji, dan tanggal. Hal ini perlu dibahas sebagai keterbatasan "
        "di BAB IV.",
        "",
        _leak_table(final),
        "",
        "## 11. Daftar keputusan praproses",
        "",
        "### Keputusan penulis",
        "",
        md_table(["#", "keputusan", "bagian"], [[i + 1, d, s] for i, (d, s) in enumerate(AUTHOR_DECISIONS)], limit=400),
        "",
        "### Keputusan yang diambil asisten (wajib tercatat)",
        "",
        md_table(["#", "keputusan", "alasan/konteks"], [[i + 1, d, s] for i, (d, s) in enumerate(OWN_DECISIONS)], limit=700),
        "",
        "## 12. Contoh 3 baris per kelas (`raw_log_masked` dari sampel uji, seperti yang diterima metode; IP disamarkan)",
        "",
        *examples,
        "## 13. Berkas keluaran",
        "",
        md_table(["berkas", "isi"], [
            ["data/processed/srbh_train.parquet, srbh_val.parquet, srbh_test.parquet",
             "split 70/15/15 dengan semua kolom, termasuk metadata label, fitur sesi (analisis saja), row_id, dan timestamp_original"],
            ["data/processed/test_sample_500.jsonl", "sampel uji untuk semua metode: masukan `raw_log_masked` + kolom parsing, kolom evaluasi `label` dan `template_key`; "
             "tanpa raw_log asli, waktu, protokol, metadata label, dan fitur sesi; urutan acak"],
            ["data/processed/srbh_excluded.parquet", "baris yang dikeluarkan gerbang bukti dan batas templat, beserta alasannya"],
            ["data/processed/label_mapping.yaml", "salinan pemetaan yang dipakai + hitungan hasil run"],
            ["reports/srbh_inspection.md", "inspeksi dataset (Langkah 2)"],
        ], limit=300),
        "",
        "## 14. Keputusan atas butir terbuka",
        "",
        "Keempat butir terbuka dari review sudah diputuskan penulis (2026-10-07) dan diterapkan di pipeline: (1) "
        f"`sample_weak_sqli = {stats['weak_sqli']}`; (2) dedup isi memakai `raw_log_masked` sebelum split; (3) metode hanya "
        "menerima `raw_log_masked` dan kolom parsing tanpa time/timestamp/protocol; (4) protokol diseragamkan HTTP/1.1 di "
        "`raw_log_masked`. Ditambah: bootstrap klaster 1.000× per `template_key`, dan pool few-shot hanya dari baris train "
        "yang isinya tidak muncul di srbh_test (`fewshot_eligible`).",
        "",
    ]
    return "\n".join(lines)
