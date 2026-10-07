"""Unduh SR-BH 2020 dari Harvard Dataverse bila belum ada, lalu verifikasi MD5.

Berkas yang sudah ada tidak pernah ditimpa: bila checksum-nya tidak cocok, proses berhenti
dengan galat agar berkas di data/raw/ tetap utuh untuk diperiksa manual.

Pemakaian: python -m src.data.download
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import urllib.request
from pathlib import Path

from .config import SRBH_CSV, SRBH_MD5, SRBH_SIZE_BYTES, SRBH_URL


def md5sum(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_srbh(path: Path = SRBH_CSV) -> str:
    """Pastikan berkas mentah ada dan identik dengan rilis Dataverse; kembalikan MD5-nya."""
    if not path.exists():
        raise FileNotFoundError(f"{path} tidak ada. Jalankan `make download` terlebih dahulu.")
    actual = md5sum(path)
    if actual != SRBH_MD5:
        raise RuntimeError(
            f"MD5 {path} = {actual}, seharusnya {SRBH_MD5}. Berkas mentah berubah atau rusak; "
            "jangan diproses sebelum diperiksa."
        )
    return actual


def download_srbh(path: Path = SRBH_CSV) -> Path:
    if path.exists():
        verify_srbh(path)
        print(f"Sudah ada dan MD5 cocok: {path}")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    print(f"Mengunduh {SRBH_URL} ({SRBH_SIZE_BYTES / 1e6:.0f} MB) ...")
    with urllib.request.urlopen(SRBH_URL, timeout=120) as resp, open(part, "wb") as out:
        shutil.copyfileobj(resp, out, length=1 << 20)
    actual = md5sum(part)
    if actual != SRBH_MD5:
        raise RuntimeError(f"MD5 unduhan {actual} != {SRBH_MD5}; berkas sementara disimpan di {part}.")
    part.rename(path)
    print(f"Tersimpan dan MD5 cocok: {path}")
    return path


if __name__ == "__main__":
    try:
        download_srbh()
    except Exception as exc:  # pesan singkat untuk pemakaian lewat make
        sys.exit(f"GAGAL: {exc}")
