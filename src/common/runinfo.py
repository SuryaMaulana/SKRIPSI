"""Metadata setiap run metode: tanggal, commit git, dan nama model (aturan umum tahap sistem)."""

from __future__ import annotations

import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PREFIXES = ("results/",)  # berkas keluaran run tidak membuat pohon kerja dianggap berubah
DOCUMENT_SUFFIXES = (".docx",)  # draf skripsi penulis: bukan kode/konfigurasi yang memengaruhi hasil


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
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_info(method: str, model: str | None, **extra) -> dict:
    """Catatan run: run_id, tanggal UTC, commit/cabang/dirty, nama model, versi Python, ditambah `extra`."""
    now = datetime.now(timezone.utc)
    git = git_state()
    return {
        "run_id": f"{method}-{now:%Y%m%dT%H%M%SZ}-{(git['git_commit'] or 'nogit')[:7]}",
        "method": method,
        "date_utc": now.isoformat(timespec="seconds"),
        **git,
        "model": model,
        "python": platform.python_version(),
        **extra,
    }
