"""Pengaturan EXVOLT X: config.yaml + nilai default yang aman."""
from __future__ import annotations

import copy
import os
import threading
from pathlib import Path

import yaml

APP_NAME = "EXVOLT X"
PUBLISHER = "EXELYN404"
BASE_DIR = Path(__file__).resolve().parents[2]

DEFAULTS = {
    "server": {"host": "127.0.0.1", "port": 8080, "auth_token": ""},
    "proxy": {
        "host": "127.0.0.1",
        "port": 8081,
        "allow_remote": False,
        "autostart": False,
        "intercept": False,
        "intercept_only_in_scope": False,
        "intercept_timeout": 300,
        "mitm_https": True,
        "verify_upstream": True,
        "ignore_hosts": [],
        "only_in_scope_history": False,
        "max_body_bytes": 5 * 1024 * 1024,
        "upstream_timeout": 30,
    },
    "history": {"max_entries": 50000},
    "network": {
        "enforce_scope": True,
        "blocked_hosts": [],
        "request_timeout": 30,
        "max_response_bytes": 10 * 1024 * 1024,
    },
    "intruder": {"max_requests": 10000, "max_concurrency": 20, "max_rps": 50},
    "session": {"autosave": True, "autosave_minutes": 5},
    "scanner": {"passive_enabled": True},
}

RANGES = {
    "server.port": (1, 65535),
    "proxy.port": (0, 65535),
    "proxy.intercept_timeout": (5, 86400),
    "proxy.max_body_bytes": (1024, 512 * 1024 * 1024),
    "proxy.upstream_timeout": (1, 600),
    "history.max_entries": (100, 5_000_000),
    "network.request_timeout": (1, 600),
    "network.max_response_bytes": (1024, 512 * 1024 * 1024),
    "intruder.max_requests": (1, 1_000_000),
    "intruder.max_concurrency": (1, 100),
    "intruder.max_rps": (1, 1000),
    "session.autosave_minutes": (1, 1440),
}


class Settings:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("EXVOLT_CONFIG") or BASE_DIR / "config.yaml")
        self.data_dir = Path(os.environ.get("EXVOLT_DATA_DIR") or BASE_DIR / "data")
        self.cert_dir = Path(os.environ.get("EXVOLT_CERT_DIR") or BASE_DIR / "certificates")
        self.lock = threading.RLock()
        self.data = copy.deepcopy(DEFAULTS)
        self.load()
        for d in (self.data_dir, self.cert_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- io
    def load(self):
        if not self.path.exists():
            return
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # file rusak: jangan sembunyikan
            raise RuntimeError(f"config.yaml tidak dapat dibaca: {exc}") from exc
        if not isinstance(raw, dict):
            raise RuntimeError("config.yaml harus berupa mapping")
        try:
            self._apply(raw, validate_only=False)
        except ValueError as exc:
            raise RuntimeError(f"config.yaml tidak valid: {exc}") from exc

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".yaml.tmp")
            tmp.write_text(yaml.safe_dump(self.data, sort_keys=False, allow_unicode=True), encoding="utf-8")
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    # --------------------------------------------------------------- api
    def get(self, dotted, default=None):
        node = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def snapshot(self, hide_secret=True):
        snap = copy.deepcopy(self.data)
        if hide_secret and snap["server"].get("auth_token"):
            snap["server"]["auth_token"] = "********"
        return snap

    def update(self, patch, persist=True):
        with self.lock:
            self._apply(patch, validate_only=False, persist=persist)

    def _apply(self, patch, validate_only=False, persist=False):
        errors, staged = [], copy.deepcopy(self.data)
        for section, values in patch.items():
            if section not in DEFAULTS or not isinstance(values, dict):
                errors.append(f"bagian tidak dikenal: {section}")
                continue
            for key, val in values.items():
                if key not in DEFAULTS[section]:
                    errors.append(f"kunci tidak dikenal: {section}.{key}")
                    continue
                if section == "server" and key == "auth_token" and val == "********":
                    continue
                err = self._check(section, key, val)
                if err:
                    errors.append(err)
                else:
                    staged[section][key] = val
        if errors:
            raise ValueError("; ".join(errors))
        self.data = staged
        if persist:
            self.save()

    @staticmethod
    def _check(section, key, val):
        name = f"{section}.{key}"
        default = DEFAULTS[section][key]
        if isinstance(default, bool):
            return None if isinstance(val, bool) else f"{name} harus boolean"
        if isinstance(default, int):
            if isinstance(val, bool) or not isinstance(val, int):
                return f"{name} harus bilangan bulat"
            lo, hi = RANGES.get(name, (0, 2**31))
            return None if lo <= val <= hi else f"{name} harus antara {lo} dan {hi}"
        if isinstance(default, str):
            if not isinstance(val, str) or len(val) > 256:
                return f"{name} harus string (maks 256)"
            if name == "server.auth_token" and val and len(val) < 16:
                return "server.auth_token minimal 16 karakter"
            if name in ("server.host", "proxy.host") and not val.strip():
                return f"{name} tidak boleh kosong"
            return None
        if isinstance(default, list):
            ok = isinstance(val, list) and len(val) <= 1000 and all(isinstance(x, str) and len(x) <= 255 for x in val)
            return None if ok else f"{name} harus daftar string"
        return f"{name} tidak didukung"


def is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1") or host.startswith("127.")
