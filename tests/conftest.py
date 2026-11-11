import asyncio, http.server, json, os, sys, threading, time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
H = {"X-Requested-With": "exvolt"}


class Target(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, code, body, ct="text/html", extra=()):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(b)))
        for k, v in extra: self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/slow"):
            time.sleep(5); return self._send(200, "slow")
        if self.path.startswith("/redir"):
            return self._send(302, "", extra=[("Location", "http://localhost:1/else")])
        if self.path.startswith("/json"):
            return self._send(200, json.dumps({"a": 1}), "application/json", [("Set-Cookie", "sid=abc123; Path=/"), ("Server", "nginx/1.18.0")])
        if self.path.startswith("/echo"):
            return self._send(200, "echo " + self.path)
        self._send(200, "<html><title>t</title><input type=password></html>", extra=[("X-Powered-By", "PHP/7.4")])
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self._send(200, self.rfile.read(n), "text/plain")


@pytest.fixture(scope="session")
def target():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("EXVOLT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("EXVOLT_CERT_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv("EXVOLT_CONFIG", str(tmp_path / "config.yaml"))
    return tmp_path


@pytest.fixture()
def client(env):
    from starlette.testclient import TestClient
    from exvolt.api.app import create_app
    from exvolt.core.settings import Settings
    app = create_app(Settings())
    with TestClient(app, base_url="http://127.0.0.1:8080") as c:
        c.h = H
        yield c


@pytest.fixture()
def services(env):
    """Layanan inti tanpa HTTP server (untuk tes proxy asyncio)."""
    from exvolt.api.app import Ctx
    from exvolt.core.settings import Settings
    s = Settings()
    s.update({"proxy": {"verify_upstream": False}}, persist=False)
    return Ctx(s)
