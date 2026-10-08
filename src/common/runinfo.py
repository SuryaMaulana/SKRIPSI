"""Metadata setiap run metode: tanggal, commit git, dan nama model (aturan umum tahap sistem)."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PREFIXES = ("results/", "reports/")  # keluaran run/evaluasi tidak membuat pohon kerja dianggap berubah
DOCUMENT_SUFFIXES = (".docx",)  # draf skripsi penulis: bukan kode/konfigurasi yang memengaruhi hasil
COMMIT_MAP = ROOT / "results" / "pemetaan_commit.json"


def _git(*args: str) -> str | None:
    try:
        done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout.rstrip("\n")


def git_state() -> dict:
    """Commit dan cabang aktif, serta apakah ada perubahan belum di-commit di luar results/."""
    status = _git("status", "--porcelain", "--untracked-files=all")
    paths = None if status is None else [line[3:].strip('"') for line in status.splitlines() if line]
    changed = None if paths is None else [
        path for path in paths
        if not path.startswith(OUTPUT_PREFIXES) and not path.lower().endswith(DOCUMENT_SUFFIXES)
    ]
    return {
        "git_commit": _git("rev-parse", "HEAD"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "git_dirty": None if changed is None else bool(changed),
        "git_dirty_paths": None if changed is None else changed[:20],
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_info(method: str, model: str | None, run_name: str | None = None, **extra) -> dict:
    """Catatan run: run_id, tanggal UTC, commit/cabang/dirty, nama model, versi Python, ditambah `extra`. run_name (mis.
    llm_single_r2) menggantikan nama metode di run_id agar run paralel yang mulai pada detik yang sama tetap unik."""
    now = datetime.now(timezone.utc)
    git = git_state()
    return {
        "run_id": f"{run_name or method}-{now:%Y%m%dT%H%M%SZ}-{(git['git_commit'] or 'nogit')[:7]}",
        "method": method,
        "date_utc": now.isoformat(timespec="seconds"),
        **git,
        "model": model,
        "python": platform.python_version(),
        **extra,
    }


def commit_terkini(commit: str | None) -> str | None:
    """Hash di riwayat git sekarang untuk commit yang tercatat di *.run.json.

    Riwayat git ditulis ulang setelah semua run selesai (reports/catatan_rekayasa.md §7): run.json dan run_id tetap
    memuat hash lama, dan results/pemetaan_commit.json memetakannya ke hash baru. Hash yang tidak ada di pemetaan
    dikembalikan apa adanya.
    """
    if not commit or not COMMIT_MAP.exists():
        return commit
    return json.loads(COMMIT_MAP.read_text(encoding="utf-8"))["lama_ke_baru"].get(commit, commit)


def repo_path(path: Path | None) -> str | None:
    """Path relatif terhadap akar repositori bila di dalamnya, selain itu path absolut (tidak pernah melempar galat)."""
    if path is None:
        return None
    path = Path(path).resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def ids_sha256(ids: list[str]) -> str:
    return hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()


RESUME_KEYS = ("input_file", "ids_file", "rows", "row_ids_sha256", "calls_file", "output_name", "model", "generation",
               "provider_routing")


def check_resume(info: dict, current: dict) -> None:
    """Run yang dilanjutkan wajib memakai masukan, daftar baris, log panggilan, nama keluaran, model, parameter generasi
    (termasuk max_tokens), dan routing yang sama dengan run awalnya; bila tidak, hentikan sebelum ada panggilan API."""
    diff = {k: (info.get(k), current.get(k)) for k in RESUME_KEYS if info.get(k) != current.get(k)}
    if diff:
        detail = "; ".join(f"{k}: awal={a!r}, sekarang={b!r}" for k, (a, b) in diff.items())
        raise RuntimeError(f"--resume dengan konfigurasi berbeda dari run awal ({detail}). Jalankan ulang perintah yang "
                           f"sama persis dengan --resume.")
