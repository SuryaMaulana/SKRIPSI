"""Langkah 2 — inspeksi SR-BH 2020 tanpa mengandaikan nama kolom.

Kolom label dikenali dari isinya (hanya 0/1); kolom "normal" dikenali sebagai kolom label yang
nilainya paling konsisten dengan "tidak ada label lain yang aktif". Nama kolom fitur hanya dipakai
di bagian profil tambahan, setelah daftar kolom dicetak di bagian 1.

Keluaran: reports/srbh_inspection.md dan data/interim/srbh_inspection.json.
Pemakaian: python -m src.data.inspect_srbh
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
from pandas.tseries.api import guess_datetime_format

from .config import INSPECTION_REPORT, INTERIM_DIR, RANDOM_STATE, SRBH_CSV, SRBH_DOI
from .download import verify_srbh
from .load import detect_label_columns, read_raw, sniff_delimiter
from .reporting import fmt_int, mask_ips, md_table, pct

TOP_COMBOS = 20
SAMPLE_CELL_LIMIT = 70

# Angka yang dipublikasikan penulis dataset (deskripsi Dataverse dan artikel), untuk pengecekan silang.
PUBLISHED = {"rows": 907_814, "normal": 525_195, "anomalous": 382_619}

# Format waktu log Apache (%t) tidak dikenali guess_datetime_format, jadi dicoba sebagai kandidat tambahan.
APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def datetime_format(nonempty: pd.Series) -> str | None:
    """Format pertama yang mengurai seluruh nilai, atau None."""
    for fmt in (guess_datetime_format(nonempty.iloc[0]), APACHE_TIME_FORMAT):
        if fmt and pd.to_datetime(nonempty.iloc[:1000], format=fmt, errors="coerce", utc=True).notna().all():
            if pd.to_datetime(nonempty, format=fmt, errors="coerce", utc=True).notna().all():
                return fmt
    return None


def infer_type(s: pd.Series) -> str:
    nonempty = s[s != ""]
    if nonempty.empty:
        return "kosong"
    if nonempty.str.fullmatch(r"-?\d+").all():
        return "integer"
    if pd.to_numeric(nonempty, errors="coerce").notna().all():
        return "float"
    fmt = datetime_format(nonempty)
    return f"datetime `{fmt}`" if fmt else "string"


def find_normal_column(y: pd.DataFrame) -> tuple[str, float]:
    """Kolom label yang paling sering bernilai 1 tepat ketika semua label lain 0."""
    total = y.sum(axis=1)
    agreement = {c: float(((y[c] == 1) == (total - y[c] == 0)).mean()) for c in y.columns}
    best = max(agreement, key=agreement.get)
    return best, agreement[best]


def combo_counts(a: np.ndarray, names: list[str]) -> list[tuple[str, int]]:
    keys = a.astype(np.int64) @ (1 << np.arange(a.shape[1], dtype=np.int64))
    counts = pd.Series(keys).value_counts()
    decode = lambda k: " + ".join(n for i, n in enumerate(names) if k >> i & 1) or "(tanpa label serangan)"
    return [(decode(int(k)), int(v)) for k, v in counts.items()]


def count_newlines(path) -> int:
    with open(path, "rb") as fh:
        return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 20), b""))


def transposed_sample(df: pd.DataFrame, rows: pd.DataFrame) -> str:
    headers = ["kolom"] + [f"baris {i}" for i in rows.index]
    body = [[c] + [mask_ips(v) for v in rows[c]] for c in df.columns]
    return md_table(headers, body, limit=SAMPLE_CELL_LIMIT)


def profile(df: pd.DataFrame, is_attack: pd.Series, attack_cols: list[str], n: int) -> tuple[list[str], dict]:
    """Fakta tambahan untuk langkah 4–8 (rekonstruksi log, sesi, split). Tidak mengambil keputusan."""
    out: list[str] = []
    stats: dict = {}

    if "timestamp" in df and (fmt := datetime_format(df["timestamp"][df["timestamp"] != ""])):
        ts_raw = df["timestamp"]
        ts = pd.to_datetime(ts_raw, format=fmt, errors="coerce", utc=True)
        frac = ts_raw.str.contains(r"\.\d", regex=True)
        offsets = ts_raw.str.extract(r"([+-]\d{4})\s*$")[0].value_counts()
        sec_counts = ts.dt.floor("s").value_counts()
        stats["timestamp"] = {
            "format": fmt, "unparsed": int(ts.isna().sum()), "min": str(ts.min()), "max": str(ts.max()),
            "fraction_with_subsecond": float(frac.mean()), "sorted": bool(ts.is_monotonic_increasing),
            "unique": int(ts.nunique()), "max_rows_same_second": int(sec_counts.max()),
            "tz_offsets": {k: int(v) for k, v in offsets.items()},
        }
        out += [
            "### Timestamp",
            f"- Contoh nilai mentah: `{ts_raw.iloc[0]}`, `{ts_raw.iloc[n // 2]}`, `{ts_raw.iloc[-1]}`",
            f"- Format terdeteksi: `{fmt}`; gagal diurai: {fmt_int(stats['timestamp']['unparsed'])}; "
            "offset zona waktu: " + ", ".join(f"`{k}` ({fmt_int(int(v))})" for k, v in offsets.items()),
            f"- Rentang: {ts.min()} s.d. {ts.max()}",
            f"- Baris dengan pecahan detik: {pct(int(frac.sum()), n)}; nilai unik: {fmt_int(stats['timestamp']['unique'])}",
            f"- Urut naik di berkas: {'ya' if stats['timestamp']['sorted'] else 'tidak'}; "
            f"maksimum baris pada detik yang sama: {fmt_int(stats['timestamp']['max_rows_same_second'])}",
            "",
        ]

    if "src_ip" in df:
        per_ip = pd.DataFrame({"ip": df["src_ip"], "attack": is_attack}).groupby("ip")["attack"].agg(["size", "sum"])
        mixed = per_ip[(per_ip["sum"] > 0) & (per_ip["sum"] < per_ip["size"])]
        top = per_ip.sort_values("size", ascending=False).head(10)
        stats["src_ip"] = {
            "unique": len(per_ip), "ips_with_attack": int((per_ip["sum"] > 0).sum()),
            "ips_mixed_normal_and_attack": len(mixed), "rows_from_mixed_ips": int(mixed["size"].sum()),
            "top10_rows": int(top["size"].sum()), "empty": int((df["src_ip"] == "").sum()),
        }
        out += [
            "### src_ip",
            f"- IP unik: {fmt_int(len(per_ip))}; IP dengan ≥1 serangan: {fmt_int(stats['src_ip']['ips_with_attack'])}; "
            f"IP campuran (normal dan serangan): {fmt_int(len(mixed))} "
            f"(menyumbang {pct(stats['src_ip']['rows_from_mixed_ips'], n)} baris)",
            f"- 10 IP teratas menyumbang {pct(stats['src_ip']['top10_rows'], n)} baris:",
            "",
            md_table(["IP (disamarkan)", "baris", "% total", "% baris IP itu yang serangan"],
                     [[mask_ips(ip), fmt_int(int(r["size"])), pct(int(r["size"]), n), pct(int(r["sum"]), int(r["size"]))]
                      for ip, r in top.iterrows()]),
            "",
        ]

    if "request_http_request" in df:
        uri = df["request_http_request"]
        stats["request_http_request"] = {
            "with_query": int(uri.str.contains("?", regex=False).sum()),
            "starts_with_slash": int(uri.str.startswith("/").sum()),
            "absolute_http": int(uri.str.match(r"(?i)https?://").sum()),
            "max_len": int(uri.str.len().max()),
        }
        odd = uri[~uri.str.startswith("/")].value_counts().head(5)
        out += [
            "### request_http_request",
            f"- Mengandung `?` (query string): {pct(stats['request_http_request']['with_query'], n)}; "
            f"diawali `/`: {pct(stats['request_http_request']['starts_with_slash'], n)}; "
            f"URI absolut `http(s)://`: {fmt_int(stats['request_http_request']['absolute_http'])}; "
            f"panjang maksimum: {fmt_int(stats['request_http_request']['max_len'])} karakter",
            "- Contoh URI yang tidak diawali `/`: " + (", ".join(f"`{mask_ips(v)[:80]}` ({fmt_int(k)})" for v, k in odd.items()) or "tidak ada"),
            "",
        ]

    if "request_body" in df:
        has_body = df["request_body"] != ""
        stats["request_body"] = {
            "nonempty": int(has_body.sum()), "nonempty_attack": int((has_body & is_attack).sum()),
            "per_label_nonempty_frac": {c: float(has_body[df[c] == "1"].mean()) for c in attack_cols},
        }
        out += [
            "### request_body (tidak ikut terekam di Combined Log Format)",
            f"- Body tidak kosong: {fmt_int(int(has_body.sum()))} baris ({pct(int(has_body.sum()), n)}); "
            f"di antara baris serangan: {pct(int((has_body & is_attack).sum()), int(is_attack.sum()))}",
            "",
            md_table(["label serangan", "% baris berlabel ini yang punya body"],
                     [[c, pct(int((has_body & (df[c] == '1')).sum()), int((df[c] == '1').sum()))] for c in attack_cols]),
            "",
        ]

    for col in ["request_http_method", "request_http_protocol", "response_http_status_code"]:
        if col in df:
            vc = df[col].value_counts()
            stats[col] = {k: int(v) for k, v in vc.head(25).items()}
            out += [f"### {col} ({fmt_int(len(vc))} nilai unik, 12 teratas)", "",
                    md_table(["nilai", "baris", "%"], [[k, fmt_int(int(v)), pct(int(v), n)] for k, v in vc.head(12).items()]), ""]

    empties = {c: int((df[c] == "").sum()) for c in df.columns}
    for col in ["response_content_length", "request_user_agent", "request_referer", "dst_ip", "request_host"]:
        if col in df:
            out.append(f"- `{col}`: kosong {pct(empties[col], n)}, nilai unik {fmt_int(df[col].nunique())}")
    out.append("")
    return out, stats


def run(df: pd.DataFrame, md5: str) -> dict:
    """Tulis laporan inspeksi untuk `df` (hasil read_raw) dan kembalikan statistiknya."""
    delimiter = sniff_delimiter(SRBH_CSV)
    n = len(df)
    newlines = count_newlines(SRBH_CSV)
    embedded_nl = {c: int(k) for c in df.columns if (k := df[c].str.contains("\n", regex=False).sum())}

    label_cols = detect_label_columns(df)
    feature_cols = [c for c in df.columns if c not in label_cols]
    y = df[label_cols].astype(np.int8)
    normal_col, normal_agreement = find_normal_column(y)
    attack_cols = [c for c in label_cols if c != normal_col]
    a = y[attack_cols].to_numpy()
    k = a.sum(axis=1)
    is_attack = pd.Series(k > 0, index=df.index)
    normal = y[normal_col].to_numpy() == 1

    types = {c: ("biner 0/1 (label)" if c in label_cols else infer_type(df[c])) for c in df.columns}
    empties = {c: int((df[c] == "").sum()) for c in df.columns}
    combos_all = combo_counts(a, attack_cols)
    multi_mask = k > 1
    combos_multi = combo_counts(a[multi_mask], attack_cols)
    cooc = a.astype(np.int64).T @ a.astype(np.int64)
    k_dist = pd.Series(k).value_counts().sort_index()

    label_rows = []
    for c in label_cols:
        cnt = int(y[c].sum())
        share_attack = pct(cnt, int(is_attack.sum())) if c != normal_col else "–"
        label_rows.append([c, fmt_int(cnt), pct(cnt, n), share_attack])

    prof_lines, prof_stats = profile(df, is_attack, attack_cols, n)

    stats = {
        "source": {"path": str(SRBH_CSV.relative_to(SRBH_CSV.parents[3])), "doi": SRBH_DOI, "md5": md5, "delimiter": delimiter},
        "rows": n, "newline_bytes": newlines, "rows_with_embedded_newline": embedded_nl,
        "columns": list(df.columns), "feature_columns": feature_cols, "label_columns": label_cols,
        "normal_column": normal_col, "normal_column_agreement": normal_agreement, "attack_columns": attack_cols,
        "types": types, "empty_counts": empties,
        "label_counts": {c: int(y[c].sum()) for c in label_cols},
        "attack_label_count_distribution": {int(i): int(v) for i, v in k_dist.items()},
        "rows_multi_attack": int(multi_mask.sum()),
        "normal_and_attack": int((normal & (k > 0)).sum()),
        "no_label_at_all": int((~normal & (k == 0)).sum()),
        "combos_all": combos_all, "combos_multi": combos_multi,
        "cooccurrence": {attack_cols[i]: {attack_cols[j]: int(cooc[i, j]) for j in range(len(attack_cols))} for i in range(len(attack_cols))},
        "profile": prof_stats,
    }
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    (INTERIM_DIR / "srbh_inspection.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    code = lambda c: c.split(" - ")[0]
    lines = [
        "# Inspeksi SR-BH 2020 (Langkah 2)",
        "",
        "Dihasilkan otomatis oleh `python -m src.data.inspect_srbh`. Alamat IPv4 pada contoh disamarkan (a.b.x.x).",
        "",
        "## 0. Sumber dan integritas",
        "",
        f"- Berkas: `{stats['source']['path']}` — Harvard Dataverse doi:{SRBH_DOI}, MD5 `{md5}` (cocok dengan metadata Dataverse)",
        f"- Pemisah terdeteksi: `{delimiter}`; encoding: UTF-8 (seluruh byte ASCII)",
        f"- Baris data terbaca: **{fmt_int(n)}** (publikasi: {fmt_int(PUBLISHED['rows'])}); "
        f"jumlah byte newline di berkas: {fmt_int(newlines)} (header + baris data + newline di dalam sel)",
        "- Sel yang mengandung newline (field ber-kutip): "
        + (", ".join(f"`{c}`: {fmt_int(v)}" for c, v in embedded_nl.items()) or "tidak ada"),
        f"- Kolom: {len(df.columns)} = {len(feature_cols)} fitur + {len(label_cols)} label (dikenali karena seluruh nilainya 0/1)",
        f"- Kolom label \"normal\" terdeteksi dari data: `{normal_col}` "
        f"(bernilai 1 tepat saat semua label lain 0 pada {pct(int(round(normal_agreement * n)), n, 4)} baris)",
        "",
        "## 1. Daftar kolom dan tipe",
        "",
        "Tipe diinferensi dari isi string mentah (semua sel dibaca sebagai teks; string kosong = tidak ada nilai).",
        "",
        md_table(["#", "kolom", "tipe terinferensi", "kosong", "nilai unik"],
                 [[i + 1, c, types[c], pct(empties[c], n), fmt_int(df[c].nunique())] for i, c in enumerate(df.columns)]),
        "",
        "## 2. Contoh baris",
        "",
        "### 5 baris pertama",
        "",
        transposed_sample(df, df.head(5)),
        "",
        f"### 5 baris acak (random_state={RANDOM_STATE})",
        "",
        transposed_sample(df, df.sample(5, random_state=RANDOM_STATE)),
        "",
        "## 3. Distribusi label",
        "",
        md_table(["label", "jumlah", "% dari semua baris", "% dari baris serangan"], label_rows),
        "",
        f"- Baris dengan ≥1 label serangan: **{fmt_int(int(is_attack.sum()))}** ({pct(int(is_attack.sum()), n)}); "
        f"publikasi: {fmt_int(PUBLISHED['anomalous'])} anomali",
        f"- Baris `{normal_col}` = 1: **{fmt_int(int(normal.sum()))}**; publikasi: {fmt_int(PUBLISHED['normal'])} normal",
        f"- Konflik `{normal_col}` = 1 sekaligus punya label serangan: **{fmt_int(stats['normal_and_attack'])}**",
        f"- Tanpa label sama sekali (normal = 0 dan tidak ada label serangan): **{fmt_int(stats['no_label_at_all'])}**",
        "",
        "## 4. Multi-label",
        "",
        md_table(["jumlah label serangan per baris", "baris", "% dari semua baris"],
                 [[int(i), fmt_int(int(v)), pct(int(v), n)] for i, v in k_dist.items()]),
        "",
        f"- Baris dengan **lebih dari satu** label serangan: **{fmt_int(int(multi_mask.sum()))}** "
        f"({pct(int(multi_mask.sum()), n)} dari semua baris; {pct(int(multi_mask.sum()), int(is_attack.sum()))} dari baris serangan)",
        "",
        f"### {TOP_COMBOS} kombinasi teratas di antara baris multi-label",
        "",
        md_table(["kombinasi", "baris", "% dari baris multi-label", "% dari semua baris"],
                 [[name, fmt_int(v), pct(v, int(multi_mask.sum())), pct(v, n)] for name, v in combos_multi[:TOP_COMBOS]]),
        "",
        f"Total kombinasi multi-label berbeda: {fmt_int(len(combos_multi))}.",
        "",
        f"### {TOP_COMBOS} kombinasi teratas di semua baris (termasuk label tunggal)",
        "",
        md_table(["kombinasi", "baris", "% dari semua baris"], [[name, fmt_int(v), pct(v, n)] for name, v in combos_all[:TOP_COMBOS]]),
        "",
        "### Matriks ko-okurensi label serangan (diagonal = total label itu)",
        "",
        md_table(["CAPEC"] + [code(c) for c in attack_cols],
                 [[c] + [fmt_int(int(cooc[i, j])) for j in range(len(attack_cols))] for i, c in enumerate(attack_cols)]),
        "",
        "## 5. Profil tambahan untuk langkah 4–8 (fakta, belum keputusan)",
        "",
        *prof_lines,
    ]
    INSPECTION_REPORT.parent.mkdir(parents=True, exist_ok=True)
    INSPECTION_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[inspeksi] baris {n} | kolom {len(df.columns)} ({len(feature_cols)} fitur + {len(label_cols)} label) | "
          f"serangan {int(is_attack.sum())} | multi-label {int(multi_mask.sum())} -> {INSPECTION_REPORT}")
    return stats


def main() -> None:
    run(read_raw(), verify_srbh())


if __name__ == "__main__":
    main()
