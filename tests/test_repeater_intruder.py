import time

def post(c, path, body=None): return c.post(path, json=body if body is not None else {}, headers=c.h)
def scope(c, host="127.0.0.1"): assert post(c, "/api/scope", {"action": "include", "type": "domain", "value": host}).status_code == 201

def test_repeater_blocked_without_scope_then_works(client, target):
    raw = f"GET /echo?z HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"
    body = {"raw": raw, "scheme": "http", "host": "127.0.0.1", "port": target}
    r = post(client, "/api/repeater/send", body)
    assert r.status_code == 403 and "scope" in r.json()["error"]
    scope(client)
    r = post(client, "/api/repeater/send", body); j = r.json()
    assert r.status_code == 200 and j["status"] == 200 and j["body"] == "echo /echo?z" and j["duration_ms"] > 0
    h = client.get(f"/api/history/{j['history_id']}").json()
    assert h["source"] == "repeater" and h["status"] == 200

def test_repeater_post_json_and_redirect_scope_check(client, target):
    scope(client)
    r = post(client, "/api/repeater/send", {"raw": f"POST /p HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{{\"a\":1}}", "scheme": "http", "host": "127.0.0.1", "port": target})
    assert r.json()["body"] == '{"a":1}'
    r = post(client, "/api/repeater/send", {"raw": "GET /redir HTTP/1.1\r\nHost: x\r\n\r\n", "scheme": "http", "host": "127.0.0.1", "port": target, "follow_redirects": True})
    j = r.json(); assert j["status"] == 302 and "tidak diikuti" in j["redirect_blocked"]    # redirect keluar scope tidak diikuti

def test_repeater_connection_error_is_reported(client):
    scope(client)
    r = post(client, "/api/repeater/send", {"raw": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "scheme": "http", "host": "127.0.0.1", "port": 1})
    assert r.status_code == 502 and r.json()["error"]

def test_saved_requests(client):
    assert post(client, "/api/repeater/saved", {"name": "a", "data": {"raw": "x"}}).status_code == 201
    items = client.get("/api/repeater/saved").json()["items"]; assert items[0]["data"] == {"raw": "x"}
    assert client.delete(f"/api/repeater/saved/{items[0]['id']}", headers=client.h).status_code == 200

def start(c, target, **kw):
    cfg = {"template": f"GET /echo?q=§a§ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n", "scheme": "http", "host": "127.0.0.1", "port": target,
           "mode": "sniper", "payloads": [["1", "2", "3"]], "concurrency": 2, "rps": 50, "confirm_target": f"127.0.0.1:{target}"}
    cfg.update(kw); return post(c, "/api/intruder/start", cfg)

def wait(c, aid, state="finished"):
    for _ in range(100):
        j = c.get(f"/api/intruder/{aid}").json()
        if j["state"] != "running": return j
        time.sleep(0.1)
    raise AssertionError("intruder tidak selesai")

def test_intruder_requires_scope_and_confirmation(client, target):
    r = start(client, target); assert r.status_code == 400 and "scope" in r.json()["error"]
    scope(client)
    r = start(client, target, confirm_target="salah"); assert r.status_code == 400 and "konfirmasi" in r.json()["error"]
    r = start(client, target, concurrency=999); assert r.status_code == 400
    r = start(client, target, payloads=[[]]); assert r.status_code == 400

def test_intruder_runs_real_requests(client, target):
    scope(client)
    r = start(client, target); assert r.status_code == 202
    j = wait(client, r.json()["id"])
    assert j["state"] == "finished" and j["done"] == 3 and j["errors"] == 0
    assert sorted(x["payload"] for x in j["results"]) == ["1", "2", "3"] and all(x["status"] == 200 and x["length"] > 0 for x in j["results"])
    csv = client.get(f"/api/intruder/{j['id']}/export").text; assert csv.startswith("n,payload,status")

def test_intruder_modes_counts(client, target):
    from exvolt.modules.intruder import estimate
    assert estimate("sniper", 2, [["a", "b"]]) == 4 and estimate("battering_ram", 2, [["a", "b"]]) == 2
    assert estimate("pitchfork", 2, [["a", "b", "c"], ["x"]]) == 1 and estimate("cluster_bomb", 2, [["a", "b"], ["x", "y", "z"]]) == 6

def test_intruder_stop_is_real(client, target):
    scope(client)
    r = start(client, target, template=f"GET /slow?q=§a§ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n", payloads=[[str(i) for i in range(20)]], concurrency=2, rps=20)
    aid = r.json()["id"]; time.sleep(0.5)
    t0 = time.time(); assert post(client, f"/api/intruder/{aid}/stop").status_code == 200
    j = wait(client, aid)
    assert j["state"] == "stopped" and time.time() - t0 < 3 and j["done"] < 20     # request /slow (5 dtk) dibatalkan, tidak ditunggu
    assert start(client, target).status_code == 202                                 # serangan baru boleh setelah stop

def test_intruder_payload_cannot_change_target(client, target):
    scope(client)
    r = start(client, target, template=f"GET §http://127.0.0.1:{target}/x§ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", payloads=[["http://evil.example/x"]])
    j = wait(client, r.json()["id"]); assert j["errors"] == 1 and j["results"][0]["status"] is None
