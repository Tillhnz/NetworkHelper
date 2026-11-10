"""Öffentliche Icons, Schriften und Skripte sind kein Fund."""
from app.exposure import verdict


def _res(raw: bytes, ctype: str):
    return {"status": 200, "raw": raw, "text": raw.decode("latin-1"), "ctype": ctype, "location": ""}


def test_icons_and_scripts_are_harmless():
    assert verdict(_res(b"\x89PNG\r\n\x1a\n" + b"x" * 500, "image/png"), None, None)[0] == "catchall"
    assert verdict(_res(b"\x89PNG\r\n\x1a\n" + b"x" * 500, ""), None, None)[0] == "catchall"
    assert verdict(_res(b"function a(){}", "application/javascript; charset=utf-8"), None, None)[0] == "catchall"


def test_svg_with_script_and_unknown_data_stay_unclear():
    assert verdict(_res(b"<svg><script>x</script></svg>", "image/svg+xml"), None, None)[0] == "unclear"
    assert verdict(_res(b"user=admin\npassword=geheim\n", "application/octet-stream"), None, None)[0] == "unclear"
