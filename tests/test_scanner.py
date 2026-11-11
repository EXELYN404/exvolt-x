import json, pytest
from exvolt.core.database import Database
from exvolt.core.event_bus import EventBus
from exvolt.core.settings import Settings
from exvolt.modules.scanner import PassiveScanner

def row(scheme="http", headers=None, body="", status=200, url=None, ct="text/html"):
    h = [("Content-Type", ct)] + (headers or [])
    return {"id": 1, "scheme": scheme, "host": "t.test", "url": url or f"{scheme}://t.test/", "method": "GET", "status": status,
            "req_headers": "[]", "resp_headers": json.dumps(h), "resp_body": body.encode(), "content_type": ct, "tls": None}

@pytest.fixture()
def sc(tmp_path, monkeypatch):
    monkeypatch.setenv("EXVOLT_DATA_DIR", str(tmp_path))
    db = Database(tmp_path / "s.db")
    return PassiveScanner(db, EventBus(), Settings(tmp_path / "c.yaml")), db

def names(db): return {f["name"] for f in db.q("SELECT name FROM findings")}

def test_headers_and_cookies(sc):
    s, db = sc
    s.analyze(row("https", [("Set-Cookie", "sid=1; Path=/"), ("Server", "Apache/2.4.1")]))
    n = names(db)
    assert "Header HSTS tidak ada" in n and "Header Content-Security-Policy tidak ada" in n
    assert "Cookie 'sid' tanpa atribut Secure" in n and "Cookie 'sid' tanpa atribut HttpOnly" in n
    assert any("server" in x for x in n)
    f = db.q("SELECT * FROM findings WHERE name LIKE 'Cookie ''sid'' tanpa atribut Secure'")[0]
    assert "sid=<disembunyikan>" in f["evidence"] and "1;" not in f["evidence"]   # nilai cookie tidak bocor ke laporan

def test_no_false_positive_on_hardened_response(sc):
    s, db = sc
    s.analyze(row("https", [("Content-Security-Policy", "default-src 'self'"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=()"), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("Strict-Transport-Security", "max-age=31536000"),
        ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")], body="<html>ok</html>"))
    assert names(db) == set()

def test_error_page_and_password_over_http(sc):
    s, db = sc
    s.analyze(row("http", body="Traceback (most recent call last):\n boom <input type=password>"))
    n = names(db)
    assert "Pesan error rinci terekspos: Stack trace Python" in n and "Form password dikirim melalui HTTP" in n

def test_dedup_and_no_response(sc):
    s, db = sc
    s.analyze(row()); s.analyze(row())
    assert db.one("SELECT COUNT(*) c FROM findings WHERE name='Header Referrer-Policy tidak ada'")["c"] == 1
    assert s.analyze(row(status=0)) == 0

def test_every_finding_has_required_fields(sc):
    s, db = sc
    s.analyze(row("http", [("Server", "nginx/1.0"), ("Set-Cookie", "a=b")], body="<html></html>"))
    for f in db.q("SELECT * FROM findings"):
        for k in ("name", "severity", "confidence", "description", "evidence", "url", "remediation"): assert f[k], k
