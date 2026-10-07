"""Emulasi semantik ModSecurity v2 untuk aturan CRS pada data yang terlihat di log akses.

Mesin acuan: ModSecurity 2.9.15 (tag v2.9.15, commit 151074a) sebagai modul Apache httpd 2.4 dengan semantik 2.4.x
terbaru (2.4.69), dikonfigurasi seperti kontainer resmi CRS (owasp/modsecurity-crs:apache): modsecurity.conf-recommended
ditambah SecUnicodeMapFile unicode.mapping 20127, MergeSlashes On, AllowEncodedSlashes Off. Fase 1 berjalan di hook
post_read_request (REQUEST_EARLY, bawaan ./configure), fase 2 di hook fixups yang dipanggil di akhir
ap_process_request_internal, setelah ap_normalize_path dan ap_unescape_url_ex.

Nilai diproses sebagai byte: setiap string disimpan sebagai str latin-1 (satu karakter = satu byte), sama seperti
ModSecurity yang bekerja pada byte mentah. Transformasi, pengurai argumen, operator, dan pencocok frasa Aho-Corasick
diporting dari sumber ModSecurity 2.9.15 (apache2/re_tfns.c, msc_util.c, msc_unicode.c, msc_parsers.c, acmp.c,
re_operators.c, re_variables.c, re.c); penguraian request-target dari httpd 2.4.69 (server/protocol.c, request.c,
util.c) dan apr-util 1.6.x (apr_uri.c). Ekspresi PCRE diterjemahkan ke `re` Python 3.11 dengan bendera DOTALL dan ASCII;
`$` diperlakukan seperti PCRE_DOLLAR_ENDONLY.

Tidak diemulasi: penolakan permintaan oleh Apache (400/404 sebelum fase 1 atau 2, mis. %2F saat AllowEncodedSlashes Off,
"/.." di atas akar, escape % tidak valid, target bukan path absolut): setiap aturan tetap dievaluasi pada setiap baris,
dengan nilai yang ditinggalkan langkah Apache bila kode kembaliannya diabaikan. Juga tidak diemulasi batas
SecPcreMatchLimit (`re` tanpa batas backtracking).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

from .crs import Link, Rule, Target, TargetRemoval, pm_phrases

NBSP = "\xa0"
_HEX = set("0123456789abcdefABCDEF")
_OCT = set("01234567")
_C_SPACE = set(" \t\n\v\f\r")  # isspace() lokal "C"
_UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_LONG_MAX = (1 << 63) - 1  # strtol() jenuh di LONG_MAX (Linux LP64)


def to_bytes_str(text: str) -> str:
    """Teks Unicode -> str latin-1 berisi byte UTF-8-nya (karakter ASCII tidak berubah)."""
    return text.encode("utf-8", "surrogatepass").decode("latin-1")


def _cstr(s: str) -> str:
    """Nilai string C (strlen): terpotong di NUL pertama."""
    return s.split("\x00", 1)[0]


# ------------------------------------------------------------------------------------------------- transformasi


def t_lowercase(s: str) -> str:
    return s.translate(_UPPER)


def _x2c(a: str, b: str) -> str:
    return chr(int(a + b, 16))


def t_url_decode(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "%" and i + 2 < n and s[i + 1] in _HEX and s[i + 2] in _HEX:
            out.append(_x2c(s[i + 1], s[i + 2]))
            i += 3
            continue
        out.append(" " if c == "+" else c)
        i += 1
    return "".join(out)


def t_url_decode_uni(s: str, unicode_map: list[int] | None = None) -> str:
    """Port urldecode_uni_nonstrict_inplace_ex(): %uHHHH lewat unicode_map_table bila SecUnicodeMapFile dipasang
    (entri -1 = tidak dipetakan); selain itu byte rendah, +0x20 untuk ASCII lebar penuh U+FF01-FF5E.

    Di kode C hanya fungsi ini yang memakai unicode_map_table; \\uHHHH pada jsDecode dan cssDecode tetap byte rendah.
    """
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "%":
            if i + 1 < n and s[i + 1] in "uU":
                if i + 5 < n and all(ch in _HEX for ch in s[i + 2:i + 6]):
                    mapped = -1 if unicode_map is None else unicode_map[int(s[i + 2:i + 6], 16)]
                    if mapped != -1:
                        out.append(chr(mapped & 0xFF))  # *d = hmap (unsigned char)
                    else:
                        b = int(s[i + 4:i + 6], 16)
                        if 0 < b < 0x5F and s[i + 2] in "fF" and s[i + 3] in "fF":
                            b += 0x20
                        out.append(chr(b))
                    i += 6
                else:
                    out.append(s[i:i + 2])  # %u tidak valid: salin apa adanya
                    i += 2
                continue
            if i + 2 < n and s[i + 1] in _HEX and s[i + 2] in _HEX:
                out.append(_x2c(s[i + 1], s[i + 2]))
                i += 3
                continue
            out.append("%")
            i += 1
            continue
        out.append(" " if c == "+" else c)
        i += 1
    return "".join(out)


def utf8_to_unicode(s: str, tail: str = "") -> tuple[str, bool]:
    """Port utf8_unicode_inplace_ex() + msre_fn_utf8Unicode_execute() 2.9.15 -> (keluaran, changed).

    Seperti C: syarat "byte kurang" memakai panjang total, bukan sisa, sehingga di ujung nilai byte lanjutan dibaca dari
    sisa buffer (`tail`, lalu NUL); NUL yang diikuti byte >= 0x80 menjadi %u00XX; kode >= U+10000 hanya menyisakan 4
    digit heksa pertama (sprintf "%u%04x" lalu maju 6 byte); keluaran dipotong di NUL pertama (strlen).
    """
    buf, n = s + tail + "\x00", len(s)
    out, i, changed = [], 0, False
    while i < n:
        c, size, d = ord(buf[i]), 0, 0
        nxt = [ord(x) for x in buf[i + 1:i + 4]]
        cont = [(b & 0xC0) == 0x80 for b in nxt] + [False] * (3 - len(nxt))
        if c & 0x80 == 0:
            if c == 0:
                size, d = 2, nxt[0]
        elif c & 0xE0 == 0xC0:
            size = -1 if n < 2 else -2 if not cont[0] else 2
            if size == 2:
                d = ((c & 0x1F) << 6) | (nxt[0] & 0x3F)
        elif c & 0xF0 == 0xE0:
            size = -1 if n < 3 else -2 if not (cont[0] and cont[1]) else 3
            if size == 3:
                d = ((c & 0x0F) << 12) | ((nxt[0] & 0x3F) << 6) | (nxt[1] & 0x3F)
        elif c & 0xF8 == 0xF0:
            size = -4 if c >= 0xF5 else -1 if n < 4 else -2 if not all(cont) else 4
            if size == 4:
                d = ((c & 0x07) << 18) | ((nxt[0] & 0x3F) << 12) | ((nxt[1] & 0x3F) << 6) | (nxt[2] & 0x3F)
        if 0xD800 <= d <= 0xDFFF:
            size = -4
        if (size == 4 and d < 0x10000) or (size == 3 and d < 0x800) or (size == 2 and d < 0x80):
            size = -3  # overlong
        if size > 0:
            out.append(("%%u%04x" % d)[:6])
            i += size
            changed = True
        else:
            out.append(buf[i])  # byte pertama tidak valid: disalin
            i += 1
    return _cstr("".join(out)), changed


def t_utf8_to_unicode(s: str) -> str:
    return utf8_to_unicode(s)[0]


# msc_html_named_entities (2.9.15): entitas WHATWG yang berupa satu kode U+0000-007F, NBSP, atau soft hyphen.
# Dicocokkan tanpa membedakan huruf besar/kecil pada seluruh token alfanumerik; panjang harus sama.
_HTML_ENTITIES = {
    "amp": "&", "apos": "'", "ast": "*", "bsol": "\\", "colon": ":", "comma": ",", "commat": "@",
    "diacriticalgrave": "`", "dollar": "$", "equals": "=", "excl": "!", "grave": "`", "gt": ">", "hat": "^",
    "lbrace": "{", "lbrack": "[", "lcub": "{", "lowbar": "_", "lpar": "(", "lsqb": "[", "lt": "<", "midast": "*",
    "nbsp": NBSP, "newline": "\n", "nonbreakingspace": NBSP, "num": "#", "percnt": "%", "period": ".", "plus": "+",
    "quest": "?", "quot": '"', "rbrace": "}", "rbrack": "]", "rcub": "}", "rpar": ")", "rsqb": "]", "semi": ";",
    "shy": "\xad", "sol": "/", "tab": "\t", "underbar": "_", "verbar": "|", "vert": "|", "verticalline": "|",
}


def t_html_entity_decode(s: str) -> str:
    """Port html_entities_decode_inplace() 2.9.15: &#D; dan &#xH; (strtol, byte rendah), entitas bernama di atas."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "&" and i + 1 < n:
            j = i + 1
            if s[j] == "#":
                if j + 1 >= n:
                    out.append(s[i:j + 1])
                    i = j + 1
                    continue
                j += 1
                hexa = s[j] in "xX"
                if hexa:
                    if j + 1 >= n:
                        out.append(s[i:j + 1])
                        i = j + 1
                        continue
                    j += 1
                k = j
                digits = _HEX if hexa else set("0123456789")
                while j < n and s[j] in digits:
                    j += 1
                if j > k:
                    out.append(chr(min(int(s[k:j], 16 if hexa else 10), _LONG_MAX) & 0xFF))
                    i = j + 1 if j < n and s[j] == ";" else j
                    continue
                out.append(s[i:k])  # "&#" atau "&#x" tanpa digit: salin
                i = k
                continue
            k = j
            while j < n and s[j].isascii() and s[j].isalnum():
                j += 1
            if j > k:
                value = _HTML_ENTITIES.get(s[k:j].lower())
                if value is not None:
                    out.append(value)
                    i = j + 1 if j < n and s[j] == ";" else j
                    continue
                out.append(s[i:j])
                i = j
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


def t_js_decode(s: str) -> str:
    out, i, n = [], 0, len(s)
    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
    while i < n:
        if s[i] != "\\":
            out.append(s[i])
            i += 1
            continue
        if i + 5 < n and s[i + 1] == "u" and all(ch in _HEX for ch in s[i + 2:i + 6]):
            b = int(s[i + 4:i + 6], 16)
            if 0 < b < 0x5F and s[i + 2] in "fF" and s[i + 3] in "fF":
                b += 0x20
            out.append(chr(b))
            i += 6
        elif i + 3 < n and s[i + 1] == "x" and s[i + 2] in _HEX and s[i + 3] in _HEX:
            out.append(_x2c(s[i + 2], s[i + 3]))
            i += 4
        elif i + 1 < n and s[i + 1] in _OCT:
            j = 0
            while i + 1 + j < n and j < 3 and s[i + 1 + j] in _OCT:
                j += 1
            if j == 3 and s[i + 1] > "3":
                j = 2  # \OOO hanya satu byte
            out.append(chr(int(s[i + 1:i + 1 + j], 8)))
            i += 1 + j
        elif i + 1 < n:
            out.append(simple.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i:])
            i = n
    return "".join(out)


def t_css_decode(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] != "\\":
            out.append(s[i])
            i += 1
            continue
        if i + 1 >= n:
            i += 1  # backslash di akhir dibuang
            continue
        i += 1
        j = 0
        while j < 6 and i + j < n and s[i + j] in _HEX:
            j += 1
        if j:
            digits = s[i:i + j]
            if j == 1:
                byte = int(digits, 16)
            else:
                byte = int(digits[-2:], 16)
            fullcheck = j == 4 or (j == 5 and digits[0] == "0") or (j == 6 and digits[:2] == "00")
            if fullcheck and 0 < byte < 0x5F and digits[-4] in "fF" and digits[-3] in "fF":
                byte += 0x20
            out.append(chr(byte))
            if i + j < n and s[i + j] in _C_SPACE:
                j += 1  # satu spasi setelah escape heksa diabaikan
            i += j
        elif s[i] == "\n":
            i += 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def t_remove_nulls(s: str) -> str:
    return s.replace("\x00", "")


def t_remove_whitespace(s: str) -> str:
    return "".join(c for c in s if c not in _C_SPACE and c != NBSP)


def t_compress_whitespace(s: str) -> str:
    out, inspace = [], False
    for c in s:
        if c in _C_SPACE or c == NBSP:
            if not inspace:
                out.append(" ")
                inspace = True
        else:
            out.append(c)
            inspace = False
    return "".join(out)


def t_replace_comments(s: str) -> str:
    out, i, n, incomment = [], 0, len(s), False
    while i < n:
        if not incomment:
            if s[i] == "/" and i + 1 < n and s[i + 1] == "*":
                incomment = True
                i += 2
            else:
                out.append(s[i])
                i += 1
        elif s[i] == "*" and i + 1 < n and s[i + 1] == "/":
            incomment = False
            out.append(" ")
            i += 2
        else:
            i += 1
    if incomment:
        out.append(" ")
    return "".join(out)


def t_remove_comments_char(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("/*", i) or s.startswith("*/", i):
            i += 2
        elif s.startswith("<!--", i):
            i += 4
        elif s.startswith("-->", i):
            i += 3
        elif s.startswith("--", i):
            i += 2
        elif s[i] == "#":
            i += 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def t_cmd_line(s: str, tail: str = "") -> str:
    """Port msre_fn_cmdline_execute(): kode C membaca buffer sampai NUL, bukan sampai panjang nilai
    (lihat transform_steps)."""
    s = _cstr(s + tail)
    out, space = [], False
    for c in s:
        if c in "\"'\\^":
            continue
        if c in " ,;\t\r\n":
            if not space:
                out.append(" ")
                space = True
        elif c in "/(":
            if space:
                out.pop()
            space = False
            out.append(c)
        else:
            out.append(c.translate(_UPPER))
            space = False
    return "".join(out)


def t_escape_seq_decode(s: str) -> str:
    out, i, n = [], 0, len(s)
    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "?": "?",
              "'": "'", '"': '"'}
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
            elif nxt in "xX" and i + 3 < n and s[i + 2] in _HEX and s[i + 3] in _HEX:
                out.append(_x2c(s[i + 2], s[i + 3]))
                i += 4
            elif nxt in _OCT:
                j = 0
                while i + 1 + j < n and j < 3 and s[i + 1 + j] in _OCT:
                    j += 1
                out.append(chr(int(s[i + 1:i + 1 + j], 8) & 0xFF))
                i += 1 + j
            else:
                out.append(nxt)  # urutan tak dikenal: backslash dibuang
                i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def normalize_path(s: str, win: bool = False) -> tuple[str, bool]:
    """Port normalize_path_inplace() ModSecurity v2 -> (keluaran, changed): buang //, /./, dan selesaikan /../ tanpa
    melewati akar.

    Alur goto pada kode C (`copy:` dan `length:`) dipertahankan lewat penanda `to_length`. Seperti C, referensi balik di
    ujung masukan dan pembuangan garis miring akhir tidak menyalakan bendera changed.
    """
    if not s:
        return s, False
    buf = list(s)
    end = len(buf) - 1
    relative = not (buf[0] == "/" or (win and buf[0] == "\\"))
    trailing = buf[end] == "/" or (win and buf[end] == "\\")
    src = dst = 0
    hitroot = done = changed = False
    while not done and src <= end and dst <= end:
        if win:
            if buf[src] == "\\":
                buf[src], changed = "/", True
            if src < end and buf[src + 1] == "\\":
                buf[src + 1], changed = "/", True
        to_length = False
        if src == end:
            done = True
        if done or buf[src + 1] == "/":  # akhir masukan atau akhir segmen: normalisasi segmen
            if src != end and buf[src] == "/":
                changed = True  # segmen kosong: ditangani bagian copy
            elif buf[src] == ".":
                if dst > 0 and buf[dst - 1] == ".":  # referensi balik "..'
                    if relative and (hitroot or dst - 2 <= 0):
                        hitroot = True
                    else:
                        dst -= 3
                        while dst > 0 and buf[dst] != "/":
                            dst -= 1
                        if dst <= 0:
                            hitroot = True
                            dst = 0
                            if not relative and src == end:
                                dst += 1
                        if done:
                            to_length = True
                        else:
                            src += 1
                            changed = True
                elif dst == 0:  # referensi diri relatif
                    changed = True
                    if done:
                        to_length = True
                    else:
                        src += 1
                elif buf[dst - 1] == "/":  # referensi diri "/."
                    changed = True
                    if done:
                        to_length = True
                    else:
                        dst -= 1
                        src += 1
            elif dst > 0:
                hitroot = False
        if to_length:
            continue
        # copy: lompati garis miring berulang, lalu salin satu byte
        if buf[src] == "/":
            old = src
            while src < end and (buf[src + 1] == "/" or (win and buf[src + 1] == "\\")):
                src += 1
            if old != src:
                changed = True
            if relative and dst == 0:
                src += 1
                continue
        buf[dst] = buf[src]
        dst += 1
        src += 1
    if not trailing and dst > 0 and buf[dst - 1] == "/":
        dst -= 1
    return "".join(buf[:dst]), changed


def t_normalize_path(s: str, win: bool = False) -> str:
    return normalize_path(s, win)[0]


def _by_content(s: str, out: str) -> tuple[str, bool]:  # bendera *changed C = isi berubah
    return out, out != s


def _by_length(s: str, out: str) -> tuple[str, bool]:  # `return (*rval_len == input_len ? 0 : 1)` dan sejenisnya
    return out, len(out) != len(s)


_NUL_ALWAYS, _NUL_NONEMPTY, _NUL_NEVER = "always", "nonempty", "never"  # kapan fungsi C menulis NUL setelah keluarannya

# nama -> (fungsi (nilai, sisa buffer, unicode map) -> (keluaran, changed), penulisan NUL penutup oleh kode C)
TRANSFORMS: dict[str, tuple[Callable[[str, str, list[int] | None], tuple[str, bool]], str]] = {
    "lowercase": (lambda s, tail, umap: _by_content(s, t_lowercase(s)), _NUL_NEVER),
    "urlDecode": (lambda s, tail, umap: _by_content(s, t_url_decode(s)), _NUL_ALWAYS),
    "urlDecodeUni": (lambda s, tail, umap: _by_content(s, t_url_decode_uni(s, umap)), _NUL_ALWAYS),
    "utf8toUnicode": (lambda s, tail, umap: utf8_to_unicode(s, tail), _NUL_ALWAYS),  # buffer baru
    "htmlEntityDecode": (lambda s, tail, umap: _by_length(s, t_html_entity_decode(s)), _NUL_NONEMPTY),
    "jsDecode": (lambda s, tail, umap: _by_length(s, t_js_decode(s)), _NUL_ALWAYS),
    "cssDecode": (lambda s, tail, umap: _by_length(s, t_css_decode(s)), _NUL_ALWAYS),
    "removeNulls": (lambda s, tail, umap: _by_length(s, t_remove_nulls(s)), _NUL_NEVER),
    "removeWhitespace": (lambda s, tail, umap: _by_length(s, t_remove_whitespace(s)), _NUL_NEVER),
    "compressWhitespace": (lambda s, tail, umap: _by_length(s, t_compress_whitespace(s)), _NUL_NEVER),
    "replaceComments": (lambda s, tail, umap: _by_length(s, t_replace_comments(s)), _NUL_NEVER),
    "removeCommentsChar": (lambda s, tail, umap: _by_length(s, t_remove_comments_char(s)), _NUL_ALWAYS),
    "cmdLine": (lambda s, tail, umap: (t_cmd_line(s, tail), True), _NUL_ALWAYS),  # selalu mengembalikan 1
    "escapeSeqDecode": (lambda s, tail, umap: _by_length(s, t_escape_seq_decode(s)), _NUL_ALWAYS),
    "normalizePath": (lambda s, tail, umap: normalize_path(s, False), _NUL_NONEMPTY),
    "normalizePathWin": (lambda s, tail, umap: normalize_path(s, True), _NUL_NONEMPTY),
}


def transform_steps(value: str, names: tuple[str, ...], unicode_map: list[int] | None = None) -> list[tuple[str, bool]]:
    """Nilai setelah tiap transformasi beserta bendera changed-nya, dengan buffer seperti re.c.

    re.c menyalin nilai sekali (apr_pstrmemdup, diakhiri NUL), lalu tiap fungsi bekerja in-place pada keluaran fungsi
    sebelumnya. Fungsi yang memendekkan nilai tanpa menulis NUL meninggalkan byte lama setelah panjang baru (`tail`,
    sampai NUL berikutnya); cmdLine (membaca sampai NUL) dan utf8toUnicode (membaca melewati panjang di ujung nilai)
    ikut membacanya.
    """
    steps, tail = [], ""
    for name in names:
        fn, nul = TRANSFORMS[name]
        out, changed = fn(value, tail, unicode_map)
        if nul == _NUL_ALWAYS or (nul == _NUL_NONEMPTY and value):
            tail = ""
        else:
            tail = _cstr((value + tail)[len(out):])
        steps.append((out, changed))
        value = out
    return steps


def _c_atol(text: str) -> int:
    m = re.match(r"[ \t\n\v\f\r]*([+-]?[0-9]+)", text)
    return int(m.group(1)) if m else 0


def _c_scan_hex(text: str, previous: int) -> int:
    """sscanf(text, "%x", &int); variabel tujuan tidak berubah bila tidak ada digit heksa."""
    m = re.match(r"[ \t\n\v\f\r]*([+-]?)(?:0[xX](?=[0-9a-fA-F]))?([0-9a-fA-F]+)", text)
    if not m:
        return previous
    value = (int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)) & 0xFFFFFFFF
    return value - (1 << 32) if value >= 1 << 31 else value


def load_unicode_map(text: str, codepage: int) -> list[int]:
    """Port unicode_map_create() (msc_unicode.c) -> unicode_map_table (65536 entri).

    Semua entri -1, lalu U+3002, U+FF61, U+FF0E, dan U+002E -> '.' (RFC 3490 §3.1). Token dipisah spasi/tab/CR/LF;
    pemetaan KODE:PETA heksa dibaca setelah token yang atol()-nya sama dengan codepage, sampai token pertama tanpa ':'
    sesudahnya. `text` = isi berkas sebagai str latin-1.
    """
    table = [-1] * 65536
    for code in (0x3002, 0xFF61, 0xFF0E, 0x002E):
        table[code] = 0x2E
    found = processing = False
    code = mapped = 0  # Code dan Map di C tidak di-reset bila sscanf gagal
    for token in re.split(r"[ \t\n\r]+", text):
        if not token:
            continue
        if _c_atol(token) == codepage:
            found = True
        if found and ":" in token:
            processing = True
            ucode, _, hmap = token.lstrip(":").partition(":")  # apr_strtok(mapping, ":", &hmap)
            code, mapped = _c_scan_hex(ucode, code), _c_scan_hex(hmap, mapped)
            if 0 <= code <= 65535:
                table[code] = mapped
        if processing and ":" not in token:
            break
    return table


# ------------------------------------------------------------------------------------------------- PCRE -> re

_POSIX = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z", "xdigit": "0-9A-Fa-f",
    "space": "\\t\\n\\x0b\\x0c\\r ", "blank": " \\t", "punct": "!-/:-@\\[-`{-~", "word": "\\w", "cntrl": "\\x00-\\x1f\\x7f",
    "print": "\\x20-\\x7e", "graph": "\\x21-\\x7e",
}


def translate_pcre(pattern: str) -> str:
    """Terjemahkan konstruksi PCRE yang berbeda arti/tidak ada di `re` Python. Konstruksi lain diteruskan apa adanya."""
    out, i, n, in_class = [], 0, len(pattern), False
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "x" and i + 2 < n and pattern[i + 2] == "{":
                close = pattern.index("}", i + 3)
                value = int(pattern[i + 3:close], 16)
                out.append(f"\\x{value:02x}" if value <= 0xFF else f"\\u{value:04x}")
                i = close + 1
                continue
            if nxt == "Q":
                close = pattern.find("\\E", i + 2)
                close = n if close < 0 else close
                out.append(re.escape(pattern[i + 2:close]))
                i = close + 2
                continue
            mapped = {
                "z": "\\Z", "e": "\\x1b",
                "h": "[\\t \\xa0]" if not in_class else "\\t \\xa0",
                "H": "[^\\t \\xa0]",
                "v": "[\\n\\x0b\\x0c\\r\\x85]" if not in_class else "\\n\\x0b\\x0c\\r\\x85",
                "V": "[^\\n\\x0b\\x0c\\r\\x85]",
                "N": "[^\\n]",
                "R": "(?:\\r\\n|[\\n\\x0b\\x0c\\r\\x85])",
            }.get(nxt)
            if nxt == "Z" and not in_class:
                mapped = "(?=\\n?\\Z)"
            out.append(mapped if mapped is not None else pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "[" and pattern.startswith("[:", i):
                close = pattern.find(":]", i + 2)
                name = pattern[i + 2:close]
                negate = name.startswith("^")
                if negate or name not in _POSIX:
                    raise ValueError(f"kelas POSIX tidak didukung: [:{name}:]")
                out.append(_POSIX[name])
                i = close + 2
                continue
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and pattern[i] == "^":
                out.append("^")
                i += 1
            if i < n and pattern[i] == "]":  # ']' pertama di kelas adalah literal
                out.append("\\]")
                i += 1
            continue
        if c == "$":
            out.append("\\Z")  # PCRE_DOLLAR_ENDONLY
            i += 1
            continue
        if pattern.startswith("(?<", i) and i + 3 < n and pattern[i + 3] not in "=!":
            out.append("(?P<")
            i += 3
            continue
        out.append(c)
        i += 1
    return "".join(out)


@lru_cache(maxsize=None)
def compile_pcre(pattern: str) -> re.Pattern:
    """Pola dibaca per byte seperti PCRE non-UTF: karakter non-ASCII literal menjadi byte UTF-8-nya masing-masing."""
    return re.compile(translate_pcre(to_bytes_str(pattern)), re.DOTALL | re.ASCII)


# --------------------------------------------------------------------------------------------- Apache: request-target

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")  # T_URI_UNRESERVED
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_C_PORT = re.compile(r"[ \t\n\v\f\r]*[+-]?[0-9]+")  # strtol() harus menghabiskan seluruh port


def _uri_path(uri: str) -> tuple[str | None, str | None]:
    """apr_uri_parse bagian deal_with_path: path sampai '?'/'#' (NULL bila kosong), query dari '?' sampai '#'."""
    path = re.match(r"[^?#]*", uri).group(0)
    rest = uri[len(path):]
    return path or None, rest[1:].split("#", 1)[0] if rest.startswith("?") else None


def _uri_authority(s: str) -> tuple[str | None, str | None] | None:
    """apr_uri_parse bagian deal_with_authority/deal_with_host; None = APR_EGENERAL."""
    hostinfo = re.match(r"[^/?#]*", s).group(0)
    host = hostinfo[hostinfo.rfind("@") + 1:]  # '@' terakhir memisahkan user:password
    if host.startswith("["):
        close = host.find("]")
        if close < 0:
            return None
        port = host[close + 2:] if host[close + 1:close + 2] == ":" else ""
    else:
        port = host.partition(":")[2]
    if port and not _C_PORT.fullmatch(port):
        return None
    return _uri_path(s[len(hostinfo):])


def apr_uri_parse(uri: str) -> tuple[str | None, str | None] | None:
    """(path, query) seperti apr_uri_parse() apr-util 1.6.x atas string C; None bila gagal (APR_EGENERAL)."""
    uri = _cstr(uri)
    if uri.startswith("/"):
        if uri[1:2] == "/" and uri[2:3] != "/":
            return _uri_authority(uri[2:])
        return _uri_path(uri)
    m = _SCHEME.match(uri)
    if m and uri[m.end():m.end() + 1] == ":":
        rest = uri[m.end() + 1:]
        return _uri_authority(rest[2:]) if rest.startswith("//") else _uri_path(rest)
    # tanpa skema: segmen pertama path relatif tidak boleh memuat ':' (RFC 3986 §3.3)
    return None if ":" in uri.split("/", 1)[0] else _uri_path(uri)


def _connect_hostinfo_ok(uri: str) -> bool:
    """apr_uri_parse_hostinfo() berhasil: host:port wajib (IPv6 dalam [])."""
    if uri.startswith("["):
        close = uri.find("]")
        if close < 0 or uri[close + 1:close + 2] != ":":
            return False
        port = uri[close + 2:]
    else:
        _, sep, port = uri.partition(":")
        if not sep:
            return False
    return bool(port) and _C_PORT.fullmatch(port) is not None


def apache_parse_uri(method: str, target: str) -> tuple[str | None, str | None]:
    """r->parsed_uri.path dan .query setelah ap_parse_uri() (httpd 2.4.69); None = NULL.

    '//' di awal diciutkan sebelum apr_uri_parse(); CONNECT memakai apr_uri_parse_hostinfo() (tanpa path/query). Bila
    penguraian gagal, Apache menjawab 400 sebelum fase 1; penolakan itu tidak diemulasi: target diurai longgar sebagai
    path (sampai '?'/'#') dan query.
    """
    uri = _cstr(target)
    while uri.startswith("//"):
        uri = uri[1:]
    if method == "CONNECT":
        return (None, None) if _connect_hostinfo_ok(uri) else _uri_path(uri)
    parsed = apr_uri_parse(uri)
    return _uri_path(uri) if parsed is None else parsed


def ap_normalize_path(path: str) -> str:
    """Port ap_normalize_path() (httpd 2.4.69, util.c) dengan bendera dari ap_process_request_internal():
    AP_NORMALIZE_NOT_ABOVE_ROOT | AP_NORMALIZE_MERGE_SLASHES (MergeSlashes On) | AP_NORMALIZE_DECODE_UNRESERVED.

    Escape %XX karakter unreserved (huruf, angka, - . _ ~) di-decode, // diciutkan, /./ dibuang, /xx/../ (juga /.%2e/)
    diselesaikan. Kode kembali 0 (400: escape tidak valid, ".." di akar, path tidak diawali '/') diabaikan.
    """
    buf = list(_cstr(path)) + ["\x00"]
    if buf[0] != "/":
        return _cstr(path)  # "*" atau path relatif: C kembali tanpa mengubah path
    r = w = 1  # posisi baca (l di kode C) dan tulis
    while buf[r] != "\x00":
        if buf[r] == "%" and buf[r + 1] in _HEX and buf[r + 2] in _HEX:
            c = _x2c(buf[r + 1], buf[r + 2])
            if c in _UNRESERVED:
                r += 2
                buf[r] = c  # huruf hasil decode menjadi posisi baca saat ini
        if buf[w - 1] == "/":
            if buf[r] == "/":  # ciutkan /////
                while buf[r] == "/":
                    r += 1
                continue
            if buf[r] == ".":
                if buf[r + 1] in "/\x00":  # buang /./
                    r += 1 if buf[r + 1] == "\x00" else 2
                    continue
                n = r + 1
                dotdot = buf[n] == "."
                if not dotdot and buf[n] == "%":
                    n += 1
                    if buf[n] == "2":
                        n += 1
                        dotdot = buf[n] in "eE"
                if dotdot and buf[n + 1] in "/\x00":  # /xx/../: mundurkan w ke segmen sebelumnya
                    if w > 1:
                        w -= 1
                        while w and buf[w - 1] != "/":
                            w -= 1
                    r = n + 1
                    if buf[r] != "\x00":
                        r += 1
                    continue
        buf[w] = buf[r]
        w += 1
        r += 1
    return "".join(buf[:w])


def ap_unescape_url_ex(url: str) -> str:
    """Port unescape_url() (httpd 2.4.69, util.c) dengan AP_UNESCAPE_URL_KEEP_UNRESERVED |
    AP_UNESCAPE_URL_FORBID_SLASHES (AllowEncodedSlashes Off): %XX unreserved dibiarkan, %2F dan %00 tetap di-decode (C
    menulisnya lalu mengembalikan 404, tidak diemulasi), escape tidak valid disalin. Hasilnya string C (terpotong di
    %00)."""
    url = _cstr(url)
    if "%" not in url:
        return url
    out, i, n = [], 0, len(url)
    while i < n:
        if url[i] != "%":
            out.append(url[i])
            i += 1
        elif i + 2 < n and url[i + 1] in _HEX and url[i + 2] in _HEX:
            c = _x2c(url[i + 1], url[i + 2])
            out.append(url[i:i + 3] if c in _UNRESERVED else c)
            i += 3
        else:
            out.append("%")  # badesc (400)
            i += 1
    return _cstr("".join(out))


def apache_phase2_path(path: str | None) -> str | None:
    """r->parsed_uri.path saat fase 2 (hook fixups): ap_normalize_path() lalu ap_unescape_url_ex() seperti
    ap_process_request_internal() httpd 2.4.69 (pre_translate_name tanpa DONE; AllowEncodedSlashes Off sehingga tidak
    ada normalisasi ulang)."""
    return None if path is None else ap_unescape_url_ex(ap_normalize_path(path))


def file_basename(path: str) -> str:
    """Port file_basename() (msc_util.c): bagian setelah '/' terakhir, lalu setelah '\\' terakhir."""
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


# ------------------------------------------------------------------------------------------------- variabel

UNAVAILABLE = {  # tidak tercatat di log akses: selalu kosong
    "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "REQUEST_BODY", "ARGS_POST", "ARGS_POST_NAMES", "FILES", "FILES_NAMES",
    "XML", "MULTIPART_PART_HEADERS", "REQUEST_BODY_LENGTH", "FILES_COMBINED_SIZE",
}
LOGGED_HEADERS = ("User-Agent", "Referer")


@dataclass
class Request:
    """Data permintaan yang terlihat di satu baris log, sebagai byte (str latin-1)."""

    method: str
    target: str  # request-target mentah (URI seperti dikirim)
    protocol: str
    headers: dict[str, str]  # hanya header yang tercatat di log (User-Agent, Referer)


def parse_query_args(query: str) -> list[tuple[str, str]]:
    """Port parse_arguments() ModSecurity v2: pisah pada '&', nama/nilai di-urlDecode (non-strict, '+' -> spasi)."""
    args, i, n = [], 0, len(query)
    while i < n:
        j = i
        while j < n and query[j] not in "=&":
            j += 1
        name = t_url_decode(query[i:j])
        if j < n and query[j] == "=":
            k = j + 1
            while k < n and query[k] != "&":
                k += 1
            args.append((name, t_url_decode(query[j + 1:k])))
            i = k + 1
        else:
            args.append((name, ""))
            i = j + 1
    return args


def _var(name: str, value: str | None) -> list[tuple[str, str]]:
    return [] if value is None else [(name, value)]  # var_simple_generate: NULL -> variabel tidak ada


def collections(req: Request) -> dict[int, dict[str, list[tuple[str, str]]]]:
    """Koleksi ModSecurity per fase {1: ..., 2: ...} yang bisa dibangun dari baris log; nama elemen dipakai untuk
    selektor dan pelaporan.

    REQUEST_FILENAME, REQUEST_BASENAME (file_basename), dan REQUEST_URI (path + "?" + query) dibaca dari
    r->parsed_uri.path saat aturan berjalan, sehingga berbeda antarfase: fase 1 = path mentah dari ap_parse_uri, fase
    2 = setelah ap_normalize_path + ap_unescape_url_ex. Variabel lain sama di kedua fase; ARGS/QUERY_STRING dari r->args
    (query mentah tanpa fragmen), REQUEST_URI_RAW = r->unparsed_uri.
    """
    path, query = apache_parse_uri(req.method, req.target)
    args = parse_query_args(query) if query is not None else []
    headers = [(k, v) for k, v in req.headers.items() if v]
    common = {
        "REQUEST_METHOD": [("REQUEST_METHOD", req.method)],
        "REQUEST_PROTOCOL": [("REQUEST_PROTOCOL", req.protocol)],
        "REQUEST_LINE": [("REQUEST_LINE", f"{req.method} {req.target} {req.protocol}")],
        "REQUEST_URI_RAW": [("REQUEST_URI_RAW", req.target)],
        "QUERY_STRING": _var("QUERY_STRING", query),
        "ARGS": args,
        "ARGS_GET": args,
        "ARGS_NAMES": [(name, name) for name, _ in args],
        "ARGS_GET_NAMES": [(name, name) for name, _ in args],
        "REQUEST_HEADERS": headers,
        "REQUEST_HEADERS_NAMES": [(k, k) for k, _ in headers],
    }
    by_phase = {}
    for phase, p in ((1, path), (2, apache_phase2_path(path))):
        uri = p if query is None else "" if p is None else f"{p}?{query}"  # apr_pstrcat(NULL, ...) = ""
        by_phase[phase] = {**common, "REQUEST_FILENAME": _var("REQUEST_FILENAME", p),
                           "REQUEST_BASENAME": _var("REQUEST_BASENAME", None if p is None else file_basename(p)),
                           "REQUEST_URI": _var("REQUEST_URI", uri)}
    return by_phase


def _phase(coll: dict[int, dict], phase: int) -> dict[str, list[tuple[str, str]]]:
    """Variabel yang dilihat aturan berfase `phase` (fase 3-5 melihat data permintaan fase 2)."""
    return coll[1] if phase == 1 else coll[2]


# ------------------------------------------------------------------------------------------------- @pm (acmp.c)


class _AcmpNode:
    __slots__ = ("letter", "text", "children", "parent", "fail", "o_match", "is_last")

    def __init__(self, letter: str, text: str, parent: _AcmpNode | None = None):
        self.letter, self.text, self.parent = letter, text, parent
        self.children: dict[str, _AcmpNode] = {}
        self.fail: _AcmpNode | None = None
        self.o_match: _AcmpNode | None = None
        self.is_last = False


class Acmp:
    """Port acmp.c (ModSecurity 2.9.15) untuk @pm/@pmFromFile: trie Aho-Corasick per byte, tanpa ACMP_USE_UTF8, tidak
    peka huruf besar/kecil (acmp_create(0, ...): tolower lokal "C" pada frasa dan data).

    Seperti acmp_connect_fail_branches(), tautan gagal hanya satu langkah: anak berhuruf sama dari simpul gagal induk,
    atau akar; jadi sebagian kecocokan yang ditemukan Aho-Corasick baku terlewat. o_match = simpul akhir-frasa pertama
    pada rantai gagal. Teks simpul = awalan frasa yang pertama kali membuat simpul itu (huruf aslinya).
    """

    def __init__(self, phrases: list[str]):
        self.root = _AcmpNode("", "")
        for phrase in phrases:  # acmp_add_pattern
            node = self.root
            for i, letter in enumerate(phrase.translate(_UPPER)):
                child = node.children.get(letter)
                if child is None:
                    child = node.children[letter] = _AcmpNode(letter, phrase[:i + 1], node)
                node = child
            if phrase:
                node.is_last = True
        nodes, level = [], list(self.root.children.values())
        while level:  # tautan gagal per tingkat (BFS)
            for node in level:
                parent = node.parent
                node.fail = self.root if parent is self.root else parent.fail.children.get(node.letter, self.root)
            nodes += level
            level = [child for node in level for child in node.children.values()]
        for node in nodes:  # acmp_connect_other_matches
            om = node.fail
            while om is not self.root:
                if om.is_last:
                    node.o_match = om
                    break
                om = om.fail

    def find(self, data: str) -> str | None:
        """acmp_process_quick() dari akar: teks simpul pada kecocokan pertama, atau None."""
        root = node = self.root
        for letter in data.translate(_UPPER):
            while True:
                go_to = node.children.get(letter)
                if go_to is not None:
                    if go_to.is_last:
                        return go_to.text
                    node = go_to
                    break
                if node is root:
                    break
                node = node.fail
            if node.o_match is not None:
                return node.text
        return None


# ------------------------------------------------------------------------------------------------- operator & evaluasi


def is_applicable(link: Link) -> bool:
    """Apakah satu link bisa bernilai dari data log (punya minimal satu target yang tersedia)."""
    for macro in re.findall(r"%\{([^}]+)\}", link.argument):
        if macro.upper().startswith("REQUEST_HEADERS.") and macro.split(".", 1)[1].lower() not in {h.lower() for h in LOGGED_HEADERS}:
            return False  # mis. %{request_headers.host}: Host tidak tercatat di log
    for t in link.targets:
        if t.exclude:
            continue
        if t.collection in ("MATCHED_VAR", "MATCHED_VARS", "MATCHED_VAR_NAME", "MATCHED_VARS_NAMES", "TX"):
            return True
        if t.collection in UNAVAILABLE:
            continue
        if t.collection == "REQUEST_HEADERS" and t.selector and not t.selector_regex:
            if t.selector.lower() not in {h.lower() for h in LOGGED_HEADERS}:
                continue
        if t.collection in {"REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_LINE", "REQUEST_URI", "REQUEST_URI_RAW",
                            "REQUEST_FILENAME", "REQUEST_BASENAME", "QUERY_STRING", "ARGS", "ARGS_GET", "ARGS_NAMES",
                            "ARGS_GET_NAMES", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"}:
            return True
    return False


@dataclass
class Match:
    variable: str  # mis. ARGS:id
    value: str  # nilai setelah transformasi (seperti MATCHED_VAR)
    data: str  # bagian yang cocok (seperti TX:0; untuk @pm teks simpul acmp)


@dataclass
class _State:
    tx: dict[str, str] = field(default_factory=dict)
    matched: list[Match] = field(default_factory=list)


def _select(target: Target, coll: dict[str, list[tuple[str, str]]], state: _State) -> list[tuple[str, str]]:
    if target.collection in ("MATCHED_VAR", "MATCHED_VARS"):
        items = [(m.variable, m.value) for m in (state.matched[-1:] if target.collection == "MATCHED_VAR" else state.matched)]
        return items
    if target.collection == "MATCHED_VAR_NAME":
        return [("MATCHED_VAR_NAME", m.variable) for m in state.matched[-1:]]
    if target.collection == "TX":
        items = [(f"TX:{k}", v) for k, v in state.tx.items()]
    else:
        items = [(f"{target.collection}:{k}" if target.collection in _KEYED else target.collection, v)
                 for k, v in coll.get(target.collection, [])]
    if target.selector is None:
        return items
    if target.selector_regex:
        rx = re.compile(target.selector, re.IGNORECASE)
        return [(k, v) for k, v in items if rx.search(k.split(":", 1)[-1])]
    want = target.selector.lower()
    return [(k, v) for k, v in items if k.split(":", 1)[-1].lower() == want]


_KEYED = {"ARGS", "ARGS_GET", "ARGS_NAMES", "ARGS_GET_NAMES", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"}


def resolve_targets(link: Link, coll: dict, state: _State) -> list[tuple[str, str]]:
    """Daftar (nama variabel, nilai) untuk satu link setelah eksklusi '!' dan penghitungan '&'."""
    chosen: list[tuple[str, str]] = []
    excluded: set[str] = set()
    for t in link.targets:
        if t.exclude:
            excluded.update(k for k, _ in _select(t, coll, state))
    for t in link.targets:
        if t.exclude:
            continue
        items = [(k, v) for k, v in _select(t, coll, state) if k not in excluded]
        if t.count:
            chosen.append((f"&{t.collection}", str(len(items))))
        else:
            chosen.extend(items)
    return chosen


def _expand(text: str, coll: dict, state: _State) -> str | None:
    """Makro %{TX.n} / %{MATCHED_VAR} / %{REQUEST_HEADERS.x}; None bila nilainya tidak tersedia di log."""
    def repl(m: re.Match) -> str:
        name = m.group(1)
        upper = name.upper()
        if upper.startswith("TX."):
            value = state.tx.get(name[3:].lower())
        elif upper == "MATCHED_VAR":
            value = state.matched[-1].value if state.matched else None
        elif upper.startswith("REQUEST_HEADERS."):
            key = name.split(".", 1)[1].lower()
            value = next((v for k, v in coll.get("REQUEST_HEADERS", []) if k.lower() == key), None)
        else:
            value = None
        if value is None:
            raise KeyError(name)
        return value
    try:
        return re.sub(r"%\{([^}]+)\}", repl, text)
    except KeyError:
        return None


class Evaluator:
    """Mengevaluasi aturan CRS pada satu permintaan; setiap aturan melihat koleksi fasenya sendiri (`collections()`).

    `phrase_files` = frasa @pmFromFile per berkas (crs.load_data_file); automaton acmp dibangun sekali per himpunan
    frasa. `removals` adalah aturan kontrol ctl:ruleRemoveTargetBy* (mis. 941010, fase 1): bila kondisinya cocok pada
    permintaan, target yang disebut tidak diperiksa oleh aturan bertag/ber-id tersebut. `unicode_map` = tabel
    SecUnicodeMapFile untuk t:urlDecodeUni (load_unicode_map).
    """

    _CACHE_CHARS = 20_000_000  # batas total karakter di cache transformasi (memori), bukan jumlah entri

    def __init__(self, phrase_files: dict[str, list[str]], removals: list[TargetRemoval] | None = None,
                 unicode_map: list[int] | None = None):
        self.phrases = dict(phrase_files)
        self.removals = list(removals or [])
        self.unicode_map = unicode_map
        self._acmp: dict[tuple[str, str], Acmp] = {}
        self._steps: dict[tuple[str, tuple[str, ...]], list[tuple[str, bool]]] = {}
        self._cached_chars = 0

    def active_removals(self, coll: dict) -> list[TargetRemoval]:
        return [r for r in self.removals if self._link(r.link, _phase(coll, r.phase), _State())]

    def _matcher(self, op: str, arg: str) -> Acmp:
        key = (op, arg)
        if key not in self._acmp:
            phrases = pm_phrases(to_bytes_str(arg)) if op == "pm" else [p for f in arg.split() for p in self.phrases[f]]
            self._acmp[key] = Acmp(phrases)
        return self._acmp[key]

    def _transform(self, value: str, names: tuple[str, ...]) -> list[tuple[str, bool]]:
        key = (value, names)
        steps = self._steps.get(key)
        if steps is None:
            steps = transform_steps(value, names, self.unicode_map)
            size = len(value) + sum(len(v) for v, _ in steps)
            if self._cached_chars + size > self._CACHE_CHARS:
                self._steps.clear()
                self._cached_chars = 0
            self._steps[key] = steps
            self._cached_chars += size
        return steps

    def _candidates(self, value: str, link: Link) -> list[str]:
        """Nilai yang diperiksa operator (re.c): tanpa multiMatch hanya hasil akhir; dengan multiMatch nilai asli dan
        nilai setelah setiap transformasi yang melaporkan perubahan."""
        if not link.transforms:
            return [value]
        steps = self._transform(value, link.transforms)
        if not link.multi_match:
            return [steps[-1][0]]
        return [value] + [v for v, changed in steps if changed]

    def _operator(self, link: Link, value: str, coll: dict, state: _State) -> tuple[bool, str, list[str] | None]:
        """(cocok, bagian yang cocok, nilai TX:0.. yang ditangkap atau None); negasi diterapkan pemanggil."""
        op, arg = link.operator, link.argument
        if op == "rx":
            m = compile_pcre(arg).search(value)
            if not m:
                return False, "", None
            last = max((i for i, g in enumerate(m.groups(), 1) if g is not None), default=0)
            groups = ["" if g is None else g for g in m.groups()[:last]]
            # msc_regexec_ex (PCRE2, ovector 30): rc = 1 + grup tertinggi yang terisi, atau 0 (tanpa TX) bila rc > 15
            return True, m.group(0), ([m.group(0)] + groups if last < 15 else None)
        if op in ("pm", "pmFromFile", "pmf"):
            if not value:
                return False, "", None  # msre_op_pm_execute: nilai kosong tidak pernah cocok
            phrase = self._matcher(op, arg).find(value)
            return phrase is not None, phrase or "", None if phrase is None else [phrase]
        expanded = _expand(arg, coll, state)
        if expanded is None:
            return False, "", None
        if op == "contains":
            return expanded in value, expanded, None
        if op == "beginsWith":
            return value.startswith(expanded), expanded, None
        if op == "endsWith":
            return value.endswith(expanded), expanded, None
        if op == "streq":
            return value == expanded, value, None
        if op == "within":
            return value in expanded, value, None
        if op == "validateByteRange":
            allowed = _byte_ranges(arg)
            bad = next((c for c in value if ord(c) not in allowed), None)
            return bad is not None, bad or "", None
        if op in ("eq", "ge", "gt", "lt", "le"):
            a, b = _atoi(value), _atoi(expanded)
            return {"eq": a == b, "ge": a >= b, "gt": a > b, "lt": a < b, "le": a <= b}[op], value, None
        raise NotImplementedError(op)

    def _link(self, link: Link, coll: dict, state: _State) -> list[Match]:
        matches = []
        for name, value in resolve_targets(link, coll, state):
            for candidate in self._candidates(value, link):
                hit, data, captured = self._operator(link, candidate, coll, state)
                if link.capture and captured is not None:  # operator mengisi TX saat cocok, sebelum negasi
                    for k in range(10):
                        state.tx.pop(str(k), None)
                    state.tx.update({str(k): v for k, v in enumerate(captured)})
                if link.negated:
                    hit, data = not hit, ""
                if hit:
                    matches.append(Match(name, candidate, data))
        return matches

    def evaluate(self, rule: Rule, coll: dict, removals: list[TargetRemoval] | None = None) -> Match | None:
        """Match pertama dari link pertama bila seluruh rantai cocok, selain itu None. `coll` = hasil collections()."""
        coll = _phase(coll, rule.phase)
        state = _State()
        first: list[Match] = []
        drop = {(r.target.collection, r.target.selector) for r in removals or []
                if (r.by == "tag" and r.selector in rule.tags) or (r.by == "id" and r.selector == str(rule.id))}
        for k, link in enumerate(rule.links):
            if drop and k == 0:
                kept = tuple(t for t in link.targets if (t.collection, t.selector) not in drop)
                link = Link(kept, link.operator, link.argument, link.negated, link.transforms, link.multi_match, link.capture)
            matches = self._link(link, coll, state)
            if not matches:
                return None
            if k == 0:
                first = matches
            state.matched = matches
        return first[0]


@lru_cache(maxsize=None)
def _byte_ranges(spec: str) -> frozenset[int]:
    allowed: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            allowed.update(range(int(a), int(b) + 1))
        elif part:
            allowed.add(int(part))
    return frozenset(allowed)


def _atoi(text: str) -> int:
    m = re.match(r"\s*([+-]?\d+)", text)
    return int(m.group(1)) if m else 0
