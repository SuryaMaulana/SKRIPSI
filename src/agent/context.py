"""Konteks baris yang sedang diproses deep agent dan pencatat panggilan (results/agent_calls.jsonl).

Baris diproses satu per satu, jadi konteks disimpan sebagai variabel modul. Alat membaca baris log ASLI dari sini,
bukan dari teks yang ditulis LLM, agar pengurai, pencocok pola, dan verifikasi evidence tidak bergantung pada salinan
yang mungkin keliru (keputusan asisten). Keluaran alat juga disimpan di sini sebagai bahan masukan sub-agen Klasifikasi.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MAX_VERIFICATION_ROUNDS = 2  # keputusan penulis: klasifikasi -> verifikasi paling banyak dua putaran


@dataclass
class RowContext:
    run_id: str
    row_id: str
    raw_log_masked: str
    attempt: int = 1
    parsed: dict | None = None
    validation: dict | None = None
    decoded: list[dict] = field(default_factory=list)
    html_decoded: list[dict] = field(default_factory=list)
    pattern_hits: list[dict] | None = None
    scanner_indicators: dict | None = None
    kb_lookups: list[str] = field(default_factory=list)
    classifications: list[dict] = field(default_factory=list)  # keluaran tervalidasi, atau {"_parse_error": alasan}
    verdicts: list[dict] = field(default_factory=list)  # satu per putaran verifikasi
    guard_blocks: list[dict] = field(default_factory=list)  # pemanggilan sub-agen yang ditahan VerificationRoundGuard
    reminders: list[str] = field(default_factory=list)  # pengingat ProcedureGuard saat orkestrator hendak berhenti
    llm_calls: int = 0
    tool_calls: int = 0
    tool_names: list[str] = field(default_factory=list)  # urutan alat yang dipanggil (termasuk task)
    delegated: set[str] = field(default_factory=set)  # sub-agen yang benar-benar dijalankan lewat task (tanpa galat)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    llm_latency_s: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # klasifikasi/verifikasi dijalankan satu per satu (guard + eksekusi atomik); terpisah dari `lock` yang dipakai di dalamnya
    procedure_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def verification_round(self) -> int:
        return len(self.verdicts)

    def rejections(self) -> int:
        return sum(not v["lolos"] for v in self.verdicts)

    def latest_classification(self) -> dict | None:
        return self.classifications[-1] if self.classifications else None

    def unverified(self) -> bool:
        """Apakah klasifikasi terakhir belum pernah diverifikasi."""
        return bool(self.classifications) and (not self.verdicts or self.verdicts[-1]["klasifikasi_ke"] < len(self.classifications))


_current: RowContext | None = None


def set_current(ctx: RowContext | None) -> None:
    global _current
    _current = ctx


def current() -> RowContext:
    if _current is None:
        raise RuntimeError("tidak ada baris yang sedang diproses")
    return _current


class CallLogger:
    """Penulis JSONL aman-utas untuk results/agent_calls.jsonl (alat bisa berjalan paralel)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        record = {"timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record}
        line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        with self._lock:
            self._file.write(line)
            self._file.flush()

    def close(self) -> None:
        self._file.close()
