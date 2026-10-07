import pandas as pd

from src.data.gate.code_injection import LABELS, RULES, evaluate
from src.data.gate.common import OUTPUT_COLUMNS

LABEL = LABELS[0]
FIELDS = ("uri_dec", "ua_dec", "ref_dec", "body_dec", "cookie_dec")
SCRIPT = "'\"<script>alert(1);</script>"
PHP_PRINT = ";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));"
SSI = '"><!--#EXEC cmd="ls /"--><'
PHP_CGI = "?-d allow_url_include=1 -d auto_prepend_file=php://input"
OUTCOME = {  # rule_id -> (candidate, reason)
    "K1": ("XSS", ""),
    "K2": ("", ""),
    "K3": ("", "OUT_OF_SCOPE"),
    "K4": ("", "OUT_OF_SCOPE"),
    "K5": ("", "HIDDEN_EVIDENCE"),
}


def frame(rows: list[dict], index: list[int] | None = None) -> pd.DataFrame:
    """Baris sintetis berlabel 242 dengan semua kolom yang dibaca modul (field kosong = "")."""
    return pd.DataFrame([{LABEL: 1, **dict.fromkeys(FIELDS, ""), **row} for row in rows], index=index)


def rules(df: pd.DataFrame) -> list[str]:
    return evaluate(df)["rule_id"].reindex(df.index).tolist()


def test_rule_follows_subtype_and_visibility():
    cases = [
        ("K1", {"ua_dec": SCRIPT}),
        ("K1", {"uri_dec": '/blog/?s=" onMouseOver="alert(1);'}),
        ("K1", {"ref_dec": "http://test-site.com/blog/?p=javascript:alert(1);"}),
        ("K2", {"uri_dec": "/wp-includes/js/jquery.js?ver=" + SSI}),
        ("K3", {"uri_dec": "/blog/" + PHP_PRINT}),
        ("K3", {"uri_dec": "/blog/${123456 654321}/index.php"}),
        ("K3", {"uri_dec": "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array"}),
        ("K3", {"uri_dec": "/wp-includes/js/jquery.min.js?ver=<!--"}),
        ("K3", {"uri_dec": "/xmlrpc.php?m=system.multicall"}),
        ("K3", {"uri_dec": '/eval-stdin.php?c=<?=md5("phpunit")?>'}),
        ("K4", {"uri_dec": "/cgi-bin/php-cgi" + PHP_CGI, "body_dec": "<?php echo 1; ?>"}),
        ("K4", {"body_dec": PHP_CGI}),
        ("K5", {"uri_dec": "/wp-login.php", "body_dec": "log=" + SCRIPT + "&pwd=x"}),
        ("K5", {"cookie_dec": "c=" + SSI}),
        ("K5", {"body_dec": '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName></methodCall>'}),
        ("K5", {"uri_dec": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "body_dec": '<?=md5("phpunit")?>'}),
        ("K5", {"uri_dec": "/index.php?p=1"}),
    ]
    df = frame([fields for _, fields in cases])
    out = evaluate(df).reindex(df.index)
    assert out["rule_id"].tolist() == [rule for rule, _ in cases]
    assert list(zip(out["candidate"], out["reason"])) == [OUTCOME[rule] for rule, _ in cases]
    assert not out["weak"].any()


def test_primary_subtype_is_chosen_by_priority_across_all_fields():
    df = frame([
        {"uri_dec": "/?s=" + SCRIPT, "body_dec": "a=" + PHP_PRINT},  # eval PHP (body) mendahului XSS (URI)
        {"uri_dec": "/?a=" + SSI + "&b=" + SCRIPT},  # SSI mendahului XSS
        {"uri_dec": "/?ver=<!--", "body_dec": "a=" + SCRIPT},  # XSS (body) mendahului '<!--' (URI)
        {"uri_dec": "/?s=" + SCRIPT, "cookie_dec": "c=" + PHP_PRINT},  # eval PHP (cookie) mendahului XSS (URI)
        {"uri_dec": "/blog/${123456 654321}/", "body_dec": "a=" + PHP_PRINT},  # eval PHP (body) mendahului EL (URI)
        {"uri_dec": "/x.php" + PHP_CGI + "&a=" + SSI},  # PHP-CGI mendahului SSI
    ])
    assert rules(df) == ["K5", "K2", "K5", "K5", "K5", "K4"]


def test_nul_bytes_in_decoded_values():
    df = frame([
        {"uri_dec": "/a\x00"},
        {"uri_dec": "/a\x00?s=" + SCRIPT},
        {"uri_dec": "/a\x00" + PHP_CGI},
        {"ua_dec": "x\x00", "body_dec": "a=\x00" + SCRIPT},
    ])
    assert rules(df) == ["K5", "K1", "K4", "K5"]


def test_output_contract_and_label_filter():
    rows = [{"uri_dec": "/?s=" + SCRIPT}, {LABEL: 0, "uri_dec": "/?s=" + SCRIPT}, {"body_dec": SCRIPT}]
    df = frame(rows, index=[907, 3, 12])
    for flags in (df, df.astype({LABEL: str})):  # label int atau string "0"/"1"
        out = evaluate(flags)
        assert list(out.columns) == OUTPUT_COLUMNS
        assert sorted(out.index) == [12, 907]
        assert set(out["label"]) == {LABEL}
    assert set(RULES) == set(OUTCOME)
