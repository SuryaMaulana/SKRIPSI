"""Pemuat aturan OWASP CRS dari berkas resmi (.conf dan .data) untuk pembanding regex.

Arsip CRS diunduh sekali ke data/external/crs/ dan diverifikasi SHA-256 (versi dipatok di configs/regex_baseline.yaml);
unicode.mapping ModSecurity 2.9.15 diunduh dengan cara yang sama ke data/external/modsecurity/. Berkas unduhan hanya
dibaca sebagai data; tidak ada kode dari arsip itu yang dijalankan. Pengurai mengikuti dua lapis sintaks:
  1. konfigurasi Apache (ap_getword_conf): token berkutip, `\\"` -> `"` dan `\\\\` -> `\\`, baris lanjutan diakhiri `\\`;
  2. bahasa aturan ModSecurity: SecRule VARIABEL "OPERATOR" "AKSI", dengan chain, capture, multiMatch, dan tag
     'paranoia-level/N'; parameter @pm dan berkas @pmFromFile diurai seperti re_operators.c 2.9.15.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..data.config import DATA_DIR

EXTERNAL_DIR = DATA_DIR / "external" / "crs"
MODSEC_DIR = DATA_DIR / "external" / "modsecurity"
_C_SPACE = " \t\n\v\f\r"  # isspace() lokal "C"
_HEX = "0123456789abcdefABCDEF"


@dataclass(frozen=True)
class Target:
    """Satu variabel aturan, mis. ARGS, !REQUEST_HEADERS:Referer, &ARGS, REQUEST_COOKIES:/__utm/."""

    collection: str
    selector: str | None = None
    selector_regex: bool = False
    exclude: bool = False
    count: bool = False

    def __str__(self) -> str:
        prefix = "!" if self.exclude else "&" if self.count else ""
        sel = "" if self.selector is None else f":/{self.selector}/" if self.selector_regex else f":{self.selector}"
        return f"{prefix}{self.collection}{sel}"


@dataclass(frozen=True)
class Link:
    """Satu SecRule di dalam rantai (chain). Aturan tanpa chain punya satu Link."""

    targets: tuple[Target, ...]
    operator: str  # nama operator tanpa '@', mis. "rx", "pmFromFile"
    argument: str
    negated: bool
    transforms: tuple[str, ...]
    multi_match: bool
    capture: bool


@dataclass(frozen=True)
class Rule:
    id: int
    file: str
    category: str  # tiga digit pertama id, mis. "942"
    paranoia: int
    severity: str
    msg: str
    links: tuple[Link, ...]
    phase: int = 2
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetRemoval:
    """Aturan kontrol `ctl:ruleRemoveTargetByTag/ById=X;VAR`: bila `link` cocok, VAR tidak diperiksa oleh aturan X.

    `link` dievaluasi dengan variabel fase aturan kontrol itu sendiri (mis. 941010 berjalan di fase 1)."""

    rule_id: int
    link: Link
    by: str  # "tag" atau "id"
    selector: str
    target: Target
    phase: int = 2


# ---------------------------------------------------------------------------------------------- unduhan terpatok


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_verified(url: str, sha256: str, path: Path) -> None:
    """Unduh `url` ke `path` bila belum ada, lalu pastikan SHA-256-nya sama dengan nilai terpatok."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        tmp = path.with_name(path.name + ".part")
        with httpx.stream("GET", url, follow_redirects=True, timeout=120) as resp:
            resp.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in resp.iter_bytes():
                    f.write(chunk)
        actual = sha256_file(tmp)
        if actual != sha256:  # unduhan rusak tidak pernah menempati nama berkas final
            tmp.unlink()
            raise RuntimeError(f"SHA-256 unduhan {path.name} tidak cocok: {actual} != {sha256}")
        tmp.rename(path)
    actual = sha256_file(path)
    if actual != sha256:
        raise RuntimeError(f"SHA-256 {path.name} tidak cocok: {actual} != {sha256} (hapus berkas itu lalu jalankan ulang)")


def ensure_unicode_mapping(url: str, sha256: str, base: Path = MODSEC_DIR) -> Path:
    """unicode.mapping ModSecurity terpatok (SecUnicodeMapFile), diunduh sekali dan diverifikasi SHA-256."""
    path = base / "unicode.mapping"
    _download_verified(url, sha256, path)
    return path


def ensure_crs(version: str, url: str, sha256: str, base: Path = EXTERNAL_DIR) -> Path:
    """Unduh (bila belum ada), verifikasi SHA-256, dan ekstrak arsip CRS; kembalikan folder akar sumbernya."""
    archive = base / f"coreruleset-{version}.tar.gz"
    _download_verified(url, sha256, archive)
    root = base / f"coreruleset-{version}"
    if root.exists() and not _matches_archive(archive, root):
        shutil.rmtree(root)  # pohon ekstraksi berbeda dari arsip terverifikasi: ekstrak ulang
    if not (root / "rules").is_dir():
        extract_dir = base / f"extract-{version}"
        with tarfile.open(archive) as tar:
            tar.extractall(extract_dir, filter="data")  # filter 'data' menolak path absolut, '..', dan symlink keluar
        (top,) = [p for p in extract_dir.iterdir() if p.is_dir()]
        top.rename(root)
        extract_dir.rmdir()
    return root


def _matches_archive(archive: Path, root: Path) -> bool:
    """Setiap berkas reguler di arsip ada di pohon ekstraksi dengan isi byte yang sama."""
    with tarfile.open(archive) as tar:
        for member in tar:
            if not member.isfile():
                continue
            target = root.joinpath(*Path(member.name).parts[1:])  # tanpa folder puncak arsip
            if not target.is_file() or target.read_bytes() != tar.extractfile(member).read():
                return False
    return True


def tree_digest(directory: Path) -> str:
    """SHA-256 atas (path relatif, isi) semua berkas di folder, berurutan; dicatat di metadata run."""
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------- sintaks konfigurasi


def logical_lines(text: str) -> list[str]:
    """Gabungkan baris lanjutan (diakhiri backslash) dan buang komentar serta baris kosong."""
    out, buf = [], ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            buf += raw[:-1]
            continue
        line = (buf + raw).strip()
        buf = ""
        if line and not line.startswith("#"):
            out.append(line)
    if buf.strip():
        out.append(buf.strip())
    return out


def split_words(line: str) -> list[str]:
    """Tokenisasi gaya ap_getword_conf: token dipisah spasi; token berkutip boleh berisi spasi.

    Di dalam kutip, hanya `\\` + kutip dan `\\` + `\\` yang di-unescape; backslash lain dibiarkan apa adanya.
    """
    words, i, n = [], 0, len(line)
    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        quote = line[i] if line[i] in "\"'" else None
        if quote:
            i += 1
            buf = []
            while i < n and line[i] != quote:
                if line[i] == "\\" and i + 1 < n and line[i + 1] in (quote, "\\"):
                    buf.append(line[i + 1])
                    i += 2
                else:
                    buf.append(line[i])
                    i += 1
            words.append("".join(buf))
            i += 1  # lewati kutip penutup
        else:
            start = i
            while i < n and not line[i].isspace():
                i += 1
            words.append(line[start:i])
    return words


def parse_actions(text: str) -> list[tuple[str, str | None]]:
    """Daftar aksi `nama[:nilai]` dipisah koma; nilai berkutip tunggal boleh memuat koma (`\\'` = kutip literal)."""
    actions, i, n = [], 0, len(text)
    while i < n:
        while i < n and (text[i].isspace() or text[i] == ","):
            i += 1
        if i >= n:
            break
        start = i
        while i < n and text[i] not in ":,":
            i += 1
        name = text[start:i].strip()
        value = None
        if i < n and text[i] == ":":
            i += 1
            while i < n and text[i] == " ":
                i += 1
            if i < n and text[i] == "'":
                i += 1
                buf = []
                while i < n and text[i] != "'":
                    if text[i] == "\\" and i + 1 < n and text[i + 1] == "'":
                        buf.append("'")
                        i += 2
                    else:
                        buf.append(text[i])
                        i += 1
                i += 1
                value = "".join(buf)
            else:
                start = i
                while i < n and text[i] != ",":
                    i += 1
                value = text[start:i].strip()
        actions.append((name, value))
    return actions


def parse_targets(text: str) -> tuple[Target, ...]:
    """Pisah variabel pada '|'. Tidak ada selektor CRS 3.3.0/4.x di kategori ini yang memuat '|' di dalam /regex/."""
    return tuple(_target(p.strip()) for p in text.split("|") if p.strip())


def _target(spec: str) -> Target:
    exclude, count = spec.startswith("!"), spec.startswith("&")
    spec = spec[1:] if exclude or count else spec
    collection, _, selector = spec.partition(":")
    if not selector:
        return Target(collection.upper(), exclude=exclude, count=count)
    if selector.startswith("'") and selector.endswith("'") and len(selector) >= 2:
        selector = selector[1:-1]
    if len(selector) >= 2 and selector.startswith("/") and selector.endswith("/"):
        return Target(collection.upper(), selector[1:-1], True, exclude, count)
    return Target(collection.upper(), selector, False, exclude, count)


def parse_operator(text: str) -> tuple[str, str, bool]:
    negated = text.startswith("!")
    text = text[1:] if negated else text
    if not text.startswith("@"):
        return "rx", text, negated  # operator implisit
    name, _, argument = text[1:].partition(" ")
    return name, argument.lstrip(), negated


# ---------------------------------------------------------------------------------------------- aturan


@dataclass
class LoadReport:
    """Ringkasan pemuatan: jumlah aturan kontrol, penghapus target (ctl), dan ketidakcocokan tag PL."""

    control_rules: int = 0
    pl_tag_mismatch: list[int] | None = None
    removals: list[TargetRemoval] | None = None


def load_rules(rules_dir: Path, categories: list[str]) -> tuple[list[Rule], LoadReport]:
    """Semua aturan deteksi (ber-tag paranoia-level) dari berkas REQUEST-<kategori>-*.conf."""
    rules: list[Rule] = []
    report = LoadReport(pl_tag_mismatch=[], removals=[])
    for category in categories:
        (conf,) = sorted(rules_dir.glob(f"REQUEST-{category}-*.conf"))
        floor = 1  # PL dari penanda "TX:DETECTION_PARANOIA_LEVEL @lt N ... skipAfter"
        pending: list[tuple[list, list[tuple[str, str | None]]]] = []
        for line in logical_lines(conf.read_text(encoding="utf-8")):
            words = split_words(line)
            if not words or words[0] != "SecRule":
                continue
            variables, operator, actions = words[1], words[2], parse_actions(words[3] if len(words) > 3 else "")
            names = {a for a, _ in actions}
            if variables.upper().startswith("TX:DETECTION_PARANOIA_LEVEL") or variables.upper().startswith("TX:EXECUTING_PARANOIA_LEVEL"):
                m = re.match(r"@lt\s+(\d+)", operator)
                if m and "skipAfter" in names:
                    floor = int(m.group(1))
                report.control_rules += 1
                continue
            pending.append((words, actions))
            if "chain" in names:
                continue
            rule = _build_rule(pending, conf.name, category)
            if rule is None:
                report.control_rules += 1
                report.removals.extend(_removals(pending))
                pending = []
                continue
            pending = []
            if rule.paranoia != floor:
                report.pl_tag_mismatch.append(rule.id)
            rules.append(rule)
    return rules, report


def _build_rule(chain: list, file: str, category: str) -> Rule | None:
    first_actions = dict()
    for name, value in chain[0][1]:
        first_actions.setdefault(name, value)
    tags = [v for n, v in chain[0][1] if n == "tag" and v]
    pl = [int(t.split("/")[1]) for t in tags if t.startswith("paranoia-level/")]
    if not pl or "id" not in first_actions:
        return None
    links = [_link(words, actions) for words, actions in chain]
    return Rule(
        id=int(first_actions["id"]),
        file=file,
        category=category,
        paranoia=pl[0],
        severity=(first_actions.get("severity") or "").upper(),
        msg=first_actions.get("msg") or "",
        links=tuple(links),
        phase=int(first_actions.get("phase") or 2),
        tags=tuple(tags),
    )


def _link(words: list[str], actions: list[tuple[str, str | None]]) -> Link:
    name, argument, negated = parse_operator(words[2])
    transforms: list[str] = []
    for a, v in actions:
        if a == "t" and v:
            transforms = [] if v == "none" else transforms + [v]
    names = {a for a, _ in actions}
    return Link(parse_targets(words[1]), name, argument, negated, tuple(transforms), "multiMatch" in names,
                "capture" in names)


def _removals(chain: list) -> list[TargetRemoval]:
    """Aksi ctl:ruleRemoveTargetByTag=TAG;VAR atau ctl:ruleRemoveTargetById=ID;VAR pada aturan kontrol tanpa chain."""
    if len(chain) != 1:
        return []
    words, actions = chain[0]
    rule_id = int(dict(actions).get("id") or 0)
    phase = int(dict(actions).get("phase") or 2)
    out = []
    for name, value in actions:
        if name != "ctl" or not value:
            continue
        m = re.match(r"ruleRemoveTargetBy(Tag|Id)=([^;]+);(.+)$", value)
        if m:
            out.append(TargetRemoval(rule_id, _link(words, actions), m.group(1).lower(), m.group(2),
                                     _target(m.group(3)), phase))
    return out


# ---------------------------------------------------------------------------------------------- frasa @pm / @pmFromFile
# Semua nilai di bawah adalah str byte (latin-1, satu karakter = satu byte) seperti char* di kode C.


def parse_pm_content(param: str) -> str | None:
    """Port parse_pm_content() (msc_util.c 2.9.15): kutip ganda pembungkus dibuang, `\\` meloloskan : ; \\ ", dan
    |41 42| menjadi byte. None bila C gagal (isi kosong atau escape lain); pemanggil lalu memakai teks asli.

    Seperti C, hasil ditulis in-place: bila tidak ada konversi, panjang tetap panjang asli (sisa buffer ikut terbawa).
    """
    content = param.split("\x00", 1)[0]
    offset = len(content) - len(content.lstrip(_C_SPACE))
    if content[offset:offset + 1] == '"' and content.endswith('"'):
        parm = content[offset + 1:-1] if len(content) - offset >= 2 else ""
    else:
        parm = content[offset:]
    if not parm:
        return None  # "Content length is 0."
    out, digits, binary, esc, converted = [], "", False, False, False
    for ch in parm:
        if ch == "|":
            binary = not binary
        elif not esc and ch == "\\":
            esc = True
        elif binary:
            if ch in _HEX:  # karakter lain di dalam |...| diabaikan
                digits += ch
                if len(digits) == 2:  # bin_offset tidak di-reset oleh '|'
                    out.append(chr(int(digits, 16)))
                    digits, converted = "", True
        elif esc:
            if ch not in ':;\\"':
                return None  # "Unsupported escape sequence."
            out.append(ch)
            esc, converted = False, True
        else:
            out.append(ch)
    return "".join(out) if converted else "".join(out) + parm[len(out):]


def pm_phrases(param: str) -> list[str]:
    """Frasa @pm seperti msre_op_pm_param_init(): parse_pm_content (teks asli bila gagal), dipotong di NUL
    (apr_pstrdup), lalu dipisah pada isspace C."""
    processed = parse_pm_content(param)
    text = (param if processed is None else processed).split("\x00", 1)[0]
    return [p for p in re.split(f"[{_C_SPACE}]+", text) if p]


def _apr_file_gets(data: str, size: int = 8192):
    """Baris seperti apr_file_gets(buf, HUGE_STRING_LEN): sampai dan termasuk '\\n', paling banyak size - 1 byte."""
    i = 0
    while i < len(data):
        j = data.find("\n", i, i + size - 1)
        end = j + 1 if j >= 0 else min(i + size - 1, len(data))
        yield data[i:end]
        i = end


def load_data_file(rules_dir: Path, name: str) -> list[str]:
    """Frasa @pmFromFile seperti msre_op_pmFromFile_param_init() 2.9.15, sebagai str byte (latin-1), urut berkas.

    Tiap baris lewat parse_pm_content, lalu dipangkas (isspace C); baris kosong dan baris berawalan '#' dilewati.
    Seperti kode C (awal == akhir setelah pemangkasan), frasa satu karakter juga dilewati.
    """
    phrases = []
    for line in _apr_file_gets((rules_dir / name).read_bytes().decode("latin-1")):
        line = line.split("\x00", 1)[0]  # strlen(buf)
        processed = parse_pm_content(line)
        text = line if processed is None else processed.split("\x00", 1)[0]
        start, end = len(text) - len(text.lstrip(_C_SPACE)), len(text)
        if end > start:
            end -= 1
        while end > start and text[end] in _C_SPACE:
            end -= 1
        if end > start:
            end += 1
        if start == end or text[start:start + 1] == "#":
            continue
        phrases.append(text[start:end])
    return phrases
