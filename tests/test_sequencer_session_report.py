import json, os, secrets, pytest
from exvolt.modules import sequencer as sq

def post(c, path, body=None): return c.post(path, json=body if body is not None else {}, headers=c.h)

def test_analysis_detects_weak_and_good_tokens():
    weak = sq.analyze([str(1000 + i) for i in range(100)])
    assert weak["numeric"]["monotonic_increasing"] and any("dapat diprediksi" in o for o in weak["observations"])
    good = sq.analyze([secrets.token_hex(16) for _ in range(300)])
    assert good["duplicates"] == 0 and good["entropy_per_char_bits"] > 3.8 and good["bit_test"]["monobit_p"] > 0.001
    dup = sq.analyze(["a1", "a1", "b2"]); assert dup["duplicates"] == 1
    with pytest.raises(sq.SequencerError): sq.analyze(["x"])

def test_extract_and_live_capture(client, services):
    row = {"resp_headers": json.dumps([["Set-Cookie", "PHPSESSID=abc; Path=/"], ["X-T", "k1"]]), "resp_body": b'{"csrf":"zzz"}'}
    assert sq.extract_from_row(row, "cookie", "PHPSESSID") == ["abc"] and sq.extract_from_row(row, "header", "X-T") == ["k1"]
    assert sq.extract_from_row(row, "body_regex", r'"csrf":"(\w+)"') == ["zzz"]
    assert post(client, "/api/sequencer/manual", {"name": "m", "text": "a\nb\nc"}).json()["added"] == 3
    assert client.get("/api/sequencer/m/analyze").json()["count"] == 3
    assert post(client, "/api/sequencer/live", {"name": "L", "kind": "body_regex", "extract": "("}).status_code == 400

def test_live_capture_from_real_proxy_traffic(services, target):
    import asyncio
    from tests.test_proxy import raw_get
    async def go():
        c = services; c.bus.bind_loop(asyncio.get_running_loop())
        c.sequencer.start_live("S", "cookie", "sid")
        await c.proxy.start("127.0.0.1", 0)
        for _ in range(3): await raw_get(c.proxy.port, target, "/json")
        await asyncio.sleep(0.5)
        assert c.sequencer.tokens("S") == ["abc123"] * 3          # hanya dari lalu lintas yang benar-benar lewat
        assert c.db.one("SELECT COUNT(*) c FROM findings")["c"] > 0   # scanner pasif berjalan pada lalu lintas yang sama
        await c.proxy.stop()
    asyncio.run(go())

def test_session_save_load_export_import_autosave(services, target):
    c = services
    c.scope.add({"action": "include", "type": "domain", "value": "x.test"})
    c.db.add_history({"ts": 1.0, "scheme": "http", "host": "x.test", "port": 80, "method": "GET", "url": "http://x.test/", "path": "/", "status": 200,
                      "req_headers": "[]", "req_body": b"\x00\xffbin", "resp_headers": "[]", "resp_body": b"R", "resp_size": 1, "in_scope": 1, "source": "proxy"})
    info = c.sessions.save("tes sesi"); assert info["name"] == "tes_sesi"
    c.db.x("DELETE FROM history"); c.scope.clear()
    c.sessions.load("tes sesi")
    r = c.db.q("SELECT * FROM history")[0]; assert r["req_body"] == b"\x00\xffbin" and c.scope.in_scope("http://x.test/")
    blob = c.sessions.export_bytes(); c.db.x("DELETE FROM history")
    assert c.sessions.import_bytes(blob)["history"] == 1 and c.db.one("SELECT COUNT(*) c FROM history")["c"] == 1
    assert c.sessions.import_bytes(blob, replace=False)["history"] == 1 and c.db.one("SELECT COUNT(*) c FROM history")["c"] == 2   # gabung
    p = c.sessions.autosave_once(); c.db.x("DELETE FROM history")
    c.sessions.recover(p.name); assert c.db.one("SELECT COUNT(*) c FROM history")["c"] == 2
    from exvolt.core.session_manager import SessionError
    with pytest.raises(SessionError): c.sessions.import_bytes(b"bukan sesi")
    with pytest.raises(SessionError): c.sessions.recover("../../etc/passwd")

def test_report_contains_only_real_findings(client, services):
    r = post(client, "/api/reports", {"title": "Kosong"}).json()
    assert r["summary"]["findings"] == 0
    html = client.get(f"/api/reports/{r['id']}/html").text; assert "Tidak ada temuan tercatat" in html
    c = client.app.state.ctx
    c.db.x("INSERT INTO findings(ts,name,severity,confidence,description,evidence,url,host,remediation,fkey) VALUES(1,'<b>X</b>','high','certain','d','ev','http://t/','t','fix','k')")
    r = post(client, "/api/reports", {"title": "Satu"}).json(); assert r["summary"]["findings"] == 1
    html = client.get(f"/api/reports/{r['id']}/html").text
    assert "&lt;b&gt;X&lt;/b&gt;" in html and "<b>X</b>" not in html            # escape HTML
    j = json.loads(client.get(f"/api/reports/{r['id']}/json").text); assert j["findings"][0]["evidence"] == "ev" and "generated_iso" in j
    assert client.get("/api/evidence/1").status_code == 200
