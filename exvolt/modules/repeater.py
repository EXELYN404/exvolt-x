"""Repeater: kirim request nyata lewat backend, hormati scope dan batasan jaringan."""
from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlsplit

from ..core import http_client
from ..utils import httpmsg as hm


class RepeaterError(ValueError):
    pass


def build_from_raw(raw_text: str, scheme: str, host: str, port: int | None):
    """Susun (method, url, headers, body) dari teks HTTP mentah + target."""
    p = hm.parse_raw_request(raw_text.encode("utf-8"))
    target = p["target"]
    if target.startswith(("http://", "https://")):
        url = target
    else:
        if not host:
            hv = hm.get_header(p["headers"], "host")
            if not hv:
                raise RepeaterError("host tidak diberikan dan header Host tidak ada")
            host = hv
        if ":" in host and not host.startswith("["):
            host, _, hp = host.partition(":")
            port = port or (int(hp) if hp.isdigit() else None)
        default = 443 if scheme == "https" else 80
        url = f"{scheme}://{host}{'' if not port or port == default else f':{port}'}{target}"
    return p["method"], url, p["headers"], p["body"]


class Repeater:
    def __init__(self, db, settings, guard, bus):
        self.db, self.settings, self.guard, self.bus = db, settings, guard, bus

    def send(self, method, url, headers, body: bytes, follow_redirects=False, timeout=None, verify=None, tab=None):
        ok, why = self.guard.check(url)
        if not ok:
            raise RepeaterError(f"request ditolak: {why}")
        timeout = timeout or self.settings.get("network.request_timeout")
        verify = self.settings.get("proxy.verify_upstream") if verify is None else verify
        try:
            r = http_client.send_request(
                method, url, headers, body, timeout=timeout, verify=verify, follow_redirects=follow_redirects,
                max_bytes=self.settings.get("network.max_response_bytes"),
                url_check=lambda u: self.guard.check(u))
        except http_client.HttpClientError as exc:
            self._log({"method": method, "url": url, "error": str(exc), "ts": time.time()})
            raise RepeaterError(str(exc)) from exc
        decoded, note = hm.decode_body(r["headers"], r["body"])
        ct = hm.get_header(r["headers"], "content-type") or ""
        view = hm.render_body(decoded, ct)
        u = urlsplit(url)
        entry = {
            "ts": time.time(), "scheme": u.scheme, "host": u.hostname, "port": u.port or (443 if u.scheme == "https" else 80),
            "method": method, "url": url, "path": (u.path or "/") + (f"?{u.query}" if u.query else ""),
            "status": r["status"], "req_headers": json.dumps(headers), "req_body": body,
            "resp_headers": json.dumps(r["headers"]), "resp_body": r["body"], "content_type": ct[:200],
            "resp_size": len(r["body"]), "req_size": len(body), "duration_ms": r["duration_ms"],
            "tls": json.dumps(r["tls"]) if r["tls"] else None, "truncated": 1 if r["truncated"] else 0,
            "in_scope": 1, "source": "repeater", "error": None}
        hid = self.db.add_history(entry, self.settings.get("history.max_entries"))
        self.bus.publish("history", {k: entry.get(k) for k in (
            "ts", "scheme", "host", "port", "method", "url", "status", "content_type", "resp_size", "duration_ms", "in_scope", "error")} | {"id": hid, "source": "repeater"})
        raw_head = f"HTTP/1.1 {r['status']} {r['reason']}\r\n" + hm.headers_to_text(r["headers"], "\r\n") + "\r\n\r\n"
        text = view["text"]
        resp = {
            "history_id": hid, "status": r["status"], "reason": r["reason"], "headers": r["headers"],
            "raw_head": raw_head, "body": text, "body_binary": view["binary"],
            "body_pretty": hm.pretty(text, ct) if not view["binary"] else text,
            "body_b64": base64.b64encode(r["body"][:2_000_000]).decode(),
            "size": len(r["body"]), "decoded_size": len(decoded), "decode_note": note,
            "truncated": r["truncated"], "duration_ms": r["duration_ms"], "ttfb_ms": r["ttfb_ms"], "tls": r["tls"],
            "redirects": r["redirects"], "redirect_blocked": r.get("redirect_blocked"), "final_url": r["url"],
            "content_type": ct}
        self._log({"ts": time.time(), "method": method, "url": url, "status": r["status"],
                   "duration_ms": r["duration_ms"], "history_id": hid})
        return resp

    def _log(self, d):
        self.db.x("INSERT INTO repeater_log(ts,data) VALUES(?,?)", (d["ts"], json.dumps(d)))
        self.db.x("DELETE FROM repeater_log WHERE id NOT IN (SELECT id FROM repeater_log ORDER BY id DESC LIMIT 500)")

    def log(self):
        return [json.loads(r["data"]) | {"id": r["id"]} for r in self.db.q("SELECT * FROM repeater_log ORDER BY id DESC LIMIT 200")]

    # ---- request tersimpan
    def save(self, name, data):
        rid, _ = self.db.x("INSERT INTO saved_requests(name,ts,data) VALUES(?,?,?)", (name[:120], time.time(), json.dumps(data)))
        return rid

    def saved(self):
        return [{"id": r["id"], "name": r["name"], "ts": r["ts"], "data": json.loads(r["data"])}
                for r in self.db.q("SELECT * FROM saved_requests ORDER BY id DESC")]

    def delete_saved(self, rid):
        return self.db.x("DELETE FROM saved_requests WHERE id=?", (rid,))[1] > 0
