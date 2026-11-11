"""Klien HTTP sinkron berbasis http.client dengan kontrol header penuh (dipakai Repeater/Intruder/Scanner)."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from ..utils import httpmsg as hm


class HttpClientError(Exception):
    pass


class RequestHandle:
    """Memungkinkan pembatalan nyata: menutup socket dari thread lain."""

    def __init__(self):
        self.conn = None
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
        c = self.conn
        if c is not None:
            try:
                if c.sock:
                    c.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                c.close()
            except Exception:
                pass


def _once(method, url, headers, body, timeout, verify, max_bytes, handle):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HttpClientError("URL harus http(s) dengan host")
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    if handle:
        if handle.cancelled:
            raise HttpClientError("dibatalkan")
        handle.conn = conn
    t0 = time.perf_counter()
    try:
        conn.connect()
        names = {k.lower() for k, _ in headers}
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if "host" not in names:
            default = 443 if parts.scheme == "https" else 80
            hv = host if port == default else f"{host}:{port}"
            conn.putheader("Host", f"[{hv}]" if ":" in host and not hv.startswith("[") else hv)
        for k, v in headers:
            conn.putheader(k, v)
        if "connection" not in names:
            conn.putheader("Connection", "close")
        if "content-length" not in names and "transfer-encoding" not in names and (body or method in ("POST", "PUT", "PATCH")):
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body or None)
        resp = conn.getresponse()
        ttfb = (time.perf_counter() - t0) * 1000
        data, truncated = bytearray(), False
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                truncated = True
                break
        tls = None
        if parts.scheme == "https" and conn.sock is not None:
            try:
                tls = {"version": conn.sock.version(), "cipher": (conn.sock.cipher() or [None])[0]}
            except Exception:
                tls = None
        return {"status": resp.status, "reason": resp.reason, "headers": [(k, v) for k, v in resp.getheaders()],
                "body": bytes(data), "truncated": truncated, "ttfb_ms": round(ttfb, 2),
                "duration_ms": round((time.perf_counter() - t0) * 1000, 2), "tls": tls, "url": url}
    except HttpClientError:
        raise
    except Exception as exc:
        if handle and handle.cancelled:
            raise HttpClientError("dibatalkan") from exc
        raise HttpClientError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            conn.close()
        except Exception:
            pass


def send_request(method, url, headers, body=b"", timeout=30, verify=True, follow_redirects=False,
                 max_bytes=10 * 1024 * 1024, handle=None, url_check=None, max_redirects=10):
    method = method.upper()
    headers = list(headers)
    redirects = []
    t0 = time.perf_counter()
    for _ in range(max_redirects + 1):
        resp = _once(method, url, headers, body, timeout, verify, max_bytes, handle)
        loc = hm.get_header(resp["headers"], "location")
        if follow_redirects and resp["status"] in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(url, loc)
            if url_check:
                ok, why = url_check(nxt)
                if not ok:
                    resp["redirect_blocked"] = f"redirect ke {nxt} tidak diikuti: {why}"
                    break
            redirects.append({"status": resp["status"], "from": url, "to": nxt})
            same_host = urlsplit(nxt).netloc == urlsplit(url).netloc
            if resp["status"] == 303 or (resp["status"] in (301, 302) and method not in ("GET", "HEAD")):
                method, body = "GET", b""
                headers = [(k, v) for k, v in headers if k.lower() not in ("content-length", "content-type")]
            if not same_host:
                headers = [(k, v) for k, v in headers
                           if k.lower() not in ("host", "authorization", "cookie")]
            else:
                headers = [(k, v) for k, v in headers if k.lower() != "host"]
            url = nxt
            continue
        break
    resp["redirects"] = redirects
    resp["duration_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return resp
