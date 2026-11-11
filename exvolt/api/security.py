"""Middleware keamanan: validasi Host (anti DNS-rebinding), CSRF, autentikasi token, header keamanan."""
from __future__ import annotations

import hmac
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from starlette.responses import JSONResponse

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
SECURITY_HEADERS = [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"), (b"content-security-policy", CSP.encode()),
                    (b"cache-control", b"no-store"), (b"cross-origin-resource-policy", b"same-origin")]
OPEN_PATHS = {"/api/health", "/api/login", "/api/auth/status"}


def _hdr(scope, name):
    n = name.encode()
    for k, v in scope["headers"]:
        if k == n:
            return v.decode("latin-1")
    return None


def host_only(hostport: str) -> str:
    h = hostport.strip().lower()
    if h.startswith("["):
        return h.split("]")[0] + "]"
    return h.split(":")[0]


class SecurityMiddleware:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    def token(self):
        return self.settings.get("server.auth_token") or ""

    def authed(self, scope):
        tok = self.token()
        if not tok:
            return True
        cookie = _hdr(scope, "cookie")
        if cookie:
            c = SimpleCookie()
            try:
                c.load(cookie)
            except Exception:
                c = {}
            if "exvolt_auth" in c and hmac.compare_digest(c["exvolt_auth"].value, tok):
                return True
        auth = _hdr(scope, "authorization") or ""
        return auth.lower().startswith("bearer ") and hmac.compare_digest(auth[7:].strip(), tok)

    def host_ok(self, scope):
        host = _hdr(scope, "host")
        if not host:
            return False
        srv_host = self.settings.get("server.host")
        if srv_host in ("127.0.0.1", "localhost", "::1"):
            return host_only(host) in LOOPBACK
        return True

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if not self.host_ok(scope):
            return await self._deny(scope, receive, send, 403, "Host tidak diizinkan")
        path = scope["path"]
        is_api = path.startswith("/api/")
        if scope["type"] == "websocket":
            origin = _hdr(scope, "origin")
            if origin and urlsplit(origin).netloc != _hdr(scope, "host"):
                return await self._deny(scope, receive, send, 403, "Origin tidak diizinkan")
            if not self.authed(scope):
                return await self._deny(scope, receive, send, 401, "Autentikasi diperlukan")
            return await self.app(scope, receive, send)
        method = scope["method"]
        if is_api and method not in ("GET", "HEAD", "OPTIONS"):
            origin = _hdr(scope, "origin")
            if origin and urlsplit(origin).netloc != _hdr(scope, "host"):
                return await self._deny(scope, receive, send, 403, "Origin lintas-situs ditolak (CSRF)")
            if _hdr(scope, "x-requested-with") != "exvolt":
                return await self._deny(scope, receive, send, 403, "Header X-Requested-With wajib")
        if is_api and path not in OPEN_PATHS and not self.authed(scope):
            return await self._deny(scope, receive, send, 401, "Autentikasi diperlukan")

        async def send_wrapped(msg):
            if msg["type"] == "http.response.start":
                headers = [(k, v) for k, v in msg.get("headers", []) if k.lower() not in {h[0] for h in SECURITY_HEADERS}]
                if not is_api and path.startswith("/assets/"):
                    headers += [h for h in SECURITY_HEADERS if h[0] != b"cache-control"] + [(b"cache-control", b"no-cache")]
                else:
                    headers += SECURITY_HEADERS
                msg = {**msg, "headers": headers}
            await send(msg)
        await self.app(scope, receive, send_wrapped)

    async def _deny(self, scope, receive, send, code, msg):
        if scope["type"] == "websocket":
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        resp = JSONResponse({"error": msg}, status_code=code, headers={"cache-control": "no-store"})
        await resp(scope, receive, send)
