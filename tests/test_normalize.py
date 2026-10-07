import pandas as pd

from src.data.normalize import decode_layers, normalize, normalize_value


def test_decodes_at_most_three_layers():
    assert decode_layers("%25253Cscript%25253E") == "<script>"
    assert decode_layers("%2525253C") == "%3C"  # lapis keempat tidak di-decode


def test_html_entities_and_keyword_case():
    assert normalize_value("&lt;SVG OnLoad=Alert(1)&gt;") == "<svg onload=alert(1)>"
    assert normalize_value("/x%27%20UNION%20ALL%20SELECT%20NULL--") == "/x' union all select null--"
    assert normalize_value("/Admin/Login") == "/Admin/Login"


def test_numbers_and_uuids():
    assert normalize_value("/wp/2020/04/914665e4-4fbd-3377-a5b2-0b4e2a9f1c3d.jpg") == "/wp/2020/04/<*>.jpg"
    assert normalize_value("/x?id=1234567&n=12345") == "/x?id=<*>&n=12345"
    assert normalize_value("ELT(5195=5195,1),0x3a6172743a") == "ELT(5195=5195,1),0x3a6172743a".replace("ELT", "elt")
    assert normalize_value("Gecko/20100101 Firefox/70.0") == "Gecko/<*> Firefox/70.0"


def test_control_characters_become_visible():
    assert normalize_value("/a%00b%0d%0aSet-cookie:x") == "/a\\x00b\\x0d\\x0aSet-cookie:x"


def test_plus_handling_per_field():
    parsed = pd.DataFrame(
        {"path": ["/a+b"], "query": ["q=a+b%2Bc"], "user_agent": ["Googlebot/2.1; +http://www.google.com/bot.html"]}
    )
    out = normalize(parsed).iloc[0]
    assert out["path_norm"] == "/a+b"
    assert out["query_norm"] == "q=a b+c"
    assert out["ua_norm"] == "Googlebot/2.1; +http://www.google.com/bot.html"


def test_missing_values_pass_through():
    parsed = pd.DataFrame({"path": [None], "query": [None], "user_agent": [None]})
    assert normalize(parsed).isna().all(axis=None)


def test_entities_need_semicolon_unless_numeric():
    assert normalize_value("q=shoes&copy=1&lang=en&notify=0", plus_as_space=True) == "q=shoes&copy=1&lang=en&notify=0"
    assert normalize_value("&lt;script&gt; &#60;b&#x3e; &#39") == "<script> <b> '"
