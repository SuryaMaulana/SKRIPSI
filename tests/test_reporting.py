from src.data.reporting import cell, fmt_dec, fmt_int, mask_ips, pct


def test_mask_ips_only_masks_addresses():
    assert mask_ips('172.26.0.1 - - "GET /pass" "-"') == '172.26.x.x - - "GET /pass" "-"'
    assert mask_ips("GET http://165.175.10.20:41200/pass") == "GET http://165.175.x.x:41200/pass"
    assert mask_ips("Chrome/33.0.193.118 Safari/534.24") == "Chrome/33.0.193.118 Safari/534.24"
    assert mask_ips("versi 1.2.3.4.5 dan 300.1.1.1") == "versi 1.2.3.4.5 dan 300.1.1.1"


def test_number_and_cell_formatting():
    assert fmt_int(907814) == "907.814"
    assert pct(1, 3) == "33,33%" and pct(1, 0) == "–"
    assert fmt_dec(0.9312) == "0,93" and fmt_dec(0.64) == "0,64"
    assert cell("a|b\nc") == "a\\|b⏎c" and cell("") == "∅"


def test_cells_escape_html_so_viewers_do_not_hide_content():
    assert cell("<script>alert(1)</script> & <!--#EXEC-->") == "\\<script>alert(1)\\</script> \\& \\<!--#EXEC-->"
