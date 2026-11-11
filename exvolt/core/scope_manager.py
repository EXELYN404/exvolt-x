"""Manajemen scope: aturan include/exclude. Tanpa aturan include => tidak ada target yang berwenang."""
from __future__ import annotations

import ipaddress
import re
import threading
from urllib.parse import urlsplit

TYPES = ("domain", "ip", "port", "url")
ACTIONS = ("include", "exclude")
_HOST_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class ScopeError(ValueError):
    pass


def split_url(url: str):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScopeError("URL harus http(s) dengan host")
    port = p.port or (443 if p.scheme == "https" else 80)
    return p.scheme, p.hostname.lower(), port


class ScopeManager:
    def __init__(self, db):
        self.db = db
        self.lock = threading.RLock()
        self._cache = None

    # ---------------------------------------------------------- validasi
    @staticmethod
    def validate(rule: dict) -> dict:
        action, typ, value = rule.get("action"), rule.get("type"), str(rule.get("value", "")).strip()
        if action not in ACTIONS:
            raise ScopeError("action harus 'include' atau 'exclude'")
        if typ not in TYPES:
            raise ScopeError(f"type harus salah satu dari {TYPES}")
        if not value or len(value) > 500:
            raise ScopeError("value kosong atau terlalu panjang")
        if typ == "domain":
            value = value.lower()
            if not _HOST_RE.match(value):
                raise ScopeError("domain tidak valid (contoh: example.com atau *.example.com)")
        elif typ == "ip":
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ScopeError(f"IP/CIDR tidak valid: {exc}") from exc
        elif typ == "port":
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise ScopeError("port harus 1-65535")
        elif typ == "url":
            if value.startswith("re:"):
                try:
                    re.compile(value[3:])
                except re.error as exc:
                    raise ScopeError(f"regex tidak valid: {exc}") from exc
            elif not value.startswith(("http://", "https://")):
                raise ScopeError("URL harus diawali http:// atau https:// (atau 're:' untuk regex)")
        return {"action": action, "type": typ, "value": value, "enabled": 1 if rule.get("enabled", True) else 0,
                "note": str(rule.get("note", ""))[:200]}

    # ---------------------------------------------------------------- crud
    def rules(self):
        with self.lock:
            if self._cache is None:
                self._cache = self.db.q("SELECT * FROM scope_rules ORDER BY id")
            return list(self._cache)

    def _dirty(self):
        self._cache = None

    def add(self, rule: dict) -> dict:
        r = self.validate(rule)
        rid, _ = self.db.x("INSERT INTO scope_rules(action,type,value,enabled,note) VALUES(?,?,?,?,?)",
                           (r["action"], r["type"], r["value"], r["enabled"], r["note"]))
        self._dirty()
        return {"id": rid, **r}

    def update(self, rid: int, enabled: bool):
        _, n = self.db.x("UPDATE scope_rules SET enabled=? WHERE id=?", (1 if enabled else 0, rid))
        self._dirty()
        return n > 0

    def delete(self, rid: int):
        _, n = self.db.x("DELETE FROM scope_rules WHERE id=?", (rid,))
        self._dirty()
        return n > 0

    def clear(self):
        self.db.x("DELETE FROM scope_rules")
        self._dirty()

    def export(self):
        return {"format": "exvolt-scope", "version": 1,
                "rules": [{k: r[k] for k in ("action", "type", "value", "enabled", "note")} for r in self.rules()]}

    def import_rules(self, data, replace=False):
        if not isinstance(data, dict) or data.get("format") != "exvolt-scope" or not isinstance(data.get("rules"), list):
            raise ScopeError("berkas scope tidak valid (format exvolt-scope diharapkan)")
        if len(data["rules"]) > 2000:
            raise ScopeError("terlalu banyak aturan (maks 2000)")
        validated = [self.validate(r) for r in data["rules"]]  # semua valid dulu, baru tulis
        if replace:
            self.clear()
        for r in validated:
            self.db.x("INSERT INTO scope_rules(action,type,value,enabled,note) VALUES(?,?,?,?,?)",
                      (r["action"], r["type"], r["value"], r["enabled"], r["note"]))
        self._dirty()
        return len(validated)

    # ------------------------------------------------------------ evaluasi
    @staticmethod
    def _match(rule, url, host, port):
        typ, val = rule["type"], rule["value"]
        if typ == "domain":
            return host.endswith(val[1:]) and host != val[2:] if val.startswith("*.") else host == val
        if typ == "ip":
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(val, strict=False)
            except ValueError:
                return False
        if typ == "port":
            return port == int(val)
        if val.startswith("re:"):
            return re.search(val[3:], url) is not None
        return url.startswith(val)

    def check(self, url: str):
        """Return (in_scope, alasan)."""
        try:
            _, host, port = split_url(url)
        except ScopeError as exc:
            return False, str(exc)
        rules = [r for r in self.rules() if r["enabled"]]
        includes = [r for r in rules if r["action"] == "include"]
        if not includes:
            return False, "scope kosong: belum ada aturan include (target tidak dianggap berwenang)"
        for r in rules:
            if r["action"] == "exclude" and self._match(r, url, host, port):
                return False, f"dikecualikan oleh aturan #{r['id']} ({r['type']}: {r['value']})"
        for r in includes:
            if self._match(r, url, host, port):
                return True, f"cocok dengan aturan #{r['id']} ({r['type']}: {r['value']})"
        return False, "tidak cocok dengan aturan include manapun"

    def in_scope(self, url: str) -> bool:
        return self.check(url)[0]

    def recompute_history(self):
        """Hitung ulang kolom in_scope untuk riwayat setelah scope berubah."""
        updates = [(1 if self.in_scope(r["url"]) else 0, r["id"])
                   for r in self.db.iterate("SELECT id, url FROM history")]
        with self.db.tx() as c:
            c.executemany("UPDATE history SET in_scope=? WHERE id=?", updates)
        return len(updates)
