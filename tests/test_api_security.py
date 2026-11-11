import json

def post(c, path, body=None, headers=None):
    return c.post(path, json=body if body is not None else {}, headers=headers if headers is not None else c.h)

def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-frame-options"] == "DENY" and "script-src 'self'" in r.headers["content-security-policy"]

def test_csrf_and_host_and_origin(client):
    assert client.post("/api/decoder/encode", json={"type": "hex", "text": "a"}).status_code == 403            # tanpa header
    bad = dict(client.h, Origin="http://evil.example")
    assert post(client, "/api/decoder/encode", {"type": "hex", "text": "a"}, bad).status_code == 403            # origin asing
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 403                      # DNS rebinding

def test_validation_errors(client):
    assert post(client, "/api/scope", {"action": "include", "type": "port", "value": "0"}).status_code == 400
    assert client.post("/api/scope", content=b"{bad", headers=client.h).status_code == 400
    assert client.get("/api/history/99999").status_code == 404
    assert client.get("/api/history/abc").status_code == 404
    assert client.get("/api/nope").status_code == 404
    assert client.put("/api/settings", json={"proxy": {"port": 99999}}, headers=client.h).status_code == 422
    assert client.put("/api/settings", json={"x": {"y": 1}}, headers=client.h).status_code == 422

def test_auth_token(env):
    from starlette.testclient import TestClient
    from exvolt.api.app import create_app
    from exvolt.core.settings import Settings
    s = Settings(); s.update({"server": {"auth_token": "a" * 20}}, persist=False)
    with TestClient(create_app(s), base_url="http://127.0.0.1:8080") as c:
        h = {"X-Requested-With": "exvolt"}
        assert c.get("/api/overview").status_code == 401
        assert c.post("/api/login", json={"token": "wrong"}, headers=h).status_code == 401
        assert c.post("/api/login", json={"token": "a" * 20}, headers=h).status_code == 200
        assert c.get("/api/overview").status_code == 200       # cookie sesi
        assert "a" * 20 not in json.dumps(c.get("/api/settings").json())   # token tidak dibocorkan

def test_settings_roundtrip_persist(client, env):
    r = client.put("/api/settings", json={"proxy": {"port": 9191, "intercept": False}}, headers=client.h)
    assert r.status_code == 200 and client.get("/api/settings").json()["settings"]["proxy"]["port"] == 9191
    assert "9191" in (env / "config.yaml").read_text()

def test_proxy_api_lifecycle(client):
    r = post(client, "/api/proxy/start", {"host": "127.0.0.1", "port": 0}); assert r.json()["running"]
    assert post(client, "/api/proxy/start", {"host": "127.0.0.1", "port": 0}).status_code == 409
    assert post(client, "/api/proxy/intercept", {"enabled": True}).json()["intercept"] is True
    assert post(client, "/api/proxy/queue/1/forward").status_code == 404
    assert client.get("/api/proxy/ca").content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert not post(client, "/api/proxy/stop").json()["running"]
    assert post(client, "/api/proxy/start", {"host": "0.0.0.0", "port": 0}).status_code == 409
