"""Sesi portabel: simpan/muat/ekspor/impor, autosave dan pemulihan."""
from __future__ import annotations

import base64
import gzip
import json
import re
import sqlite3
import threading
import time
from pathlib import Path

FORMAT = "exvolt-session"
VERSION = 1
BLOB_COLS = {"history": ("req_body", "resp_body"), "ws_messages": ("payload",)}
TABLES = ("history", "findings", "ws_messages", "scope_rules", "token_sets", "tokens", "saved_requests")
MAX_IMPORT_BYTES = 512 * 1024 * 1024


class SessionError(ValueError):
    pass


def _safe_name(name: str) -> str:
    n = re.sub(r"[^\w.-]+", "_", name.strip())[:80].strip("._")
    if not n:
        raise SessionError("nama sesi tidak valid")
    return n


class SessionManager:
    def __init__(self, settings, db, bus):
        self.settings, self.db, self.bus = settings, db, bus
        self.dir = settings.data_dir / "sessions"
        self.auto_dir = settings.data_dir / "autosave"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.auto_dir.mkdir(parents=True, exist_ok=True)
        self.current = {"name": None, "saved": None}
        self._stop = threading.Event()
        self._thread = None
        self._last_changes = -1

    # --------------------------------------------------------- serialisasi
    def _dump(self, meta=None):
        out = {"format": FORMAT, "version": VERSION, "created": time.time(), "meta": meta or {}, "tables": {}}
        for t in TABLES:
            rows = []
            for r in self.db.iterate(f"SELECT * FROM {t}"):
                for c in BLOB_COLS.get(t, ()):
                    if r.get(c) is not None:
                        r[c] = base64.b64encode(r[c] if isinstance(r[c], bytes) else str(r[c]).encode()).decode()
                rows.append(r)
            out["tables"][t] = rows
        out["meta"]["counts"] = {t: len(v) for t, v in out["tables"].items()}
        return out

    def export_bytes(self, name="session"):
        return gzip.compress(json.dumps(self._dump({"name": name, "app": "EXVOLT X"}), ensure_ascii=False).encode("utf-8"))

    @staticmethod
    def parse(data: bytes):
        if len(data) > MAX_IMPORT_BYTES:
            raise SessionError("berkas sesi terlalu besar")
        try:
            raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise SessionError(f"berkas sesi tidak dapat dibaca: {exc}") from exc
        if not isinstance(doc, dict) or doc.get("format") != FORMAT or not isinstance(doc.get("tables"), dict):
            raise SessionError("bukan berkas sesi EXVOLT X yang valid")
        if doc.get("version") != VERSION:
            raise SessionError(f"versi sesi {doc.get('version')} tidak didukung")
        return doc

    def import_bytes(self, data: bytes, replace=True):
        doc = self.parse(data)
        tables = doc["tables"]
        with self.db.tx() as c:
            if replace:
                for t in reversed(TABLES):
                    c.execute(f"DELETE FROM {t}")
            idmap = {}
            for t in TABLES:
                rows = tables.get(t, [])
                if not isinstance(rows, list) or not rows:
                    continue
                cols_db = [r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()]
                for r in rows:
                    if not isinstance(r, dict):
                        raise SessionError(f"baris tidak valid pada tabel {t}")
                    r = {k: v for k, v in r.items() if k in cols_db}
                    for col in BLOB_COLS.get(t, ()):
                        if r.get(col) is not None:
                            r[col] = base64.b64decode(r[col])
                    old = r.pop("id", None) if (not replace and t in ("history", "findings", "ws_messages", "tokens")) else r.get("id")
                    if not replace and t == "findings" and r.get("history_id") in idmap.get("history", {}):
                        r["history_id"] = idmap["history"][r["history_id"]]
                    if not replace and t == "ws_messages" and r.get("conn_id") in idmap.get("history", {}):
                        r["conn_id"] = idmap["history"][r["conn_id"]]
                    keys = list(r)
                    cur = c.execute(f"INSERT OR IGNORE INTO {t}({','.join(keys)}) VALUES({','.join('?' * len(keys))})",
                                    [r[k] for k in keys])
                    if old is not None and not replace:
                        idmap.setdefault(t, {})[old] = cur.lastrowid
        counts = {t: len(tables.get(t, [])) for t in TABLES}
        return counts

    # ------------------------------------------------------- simpan / muat
    def _path(self, name):
        return self.dir / f"{_safe_name(name)}.exvolt"

    def save(self, name):
        p = self._path(name)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(self.export_bytes(name))
        tmp.replace(p)
        self.current = {"name": p.stem, "saved": time.time()}
        return self.info(p)

    def load(self, name, replace=True):
        p = self._path(name)
        if not p.exists():
            raise SessionError("sesi tidak ditemukan")
        counts = self.import_bytes(p.read_bytes(), replace=replace)
        self.current = {"name": p.stem, "saved": p.stat().st_mtime}
        return counts

    def delete(self, name):
        p = self._path(name)
        if not p.exists():
            return False
        p.unlink()
        return True

    @staticmethod
    def info(p: Path):
        st = p.stat()
        return {"name": p.stem, "size": st.st_size, "modified": st.st_mtime}

    def list(self):
        return sorted((self.info(p) for p in self.dir.glob("*.exvolt")), key=lambda x: -x["modified"])

    # ---------------------------------------------------------- autosave
    def autosave_once(self):
        """Salinan konsisten database memakai SQLite backup API."""
        target = self.auto_dir / f"autosave-{time.strftime('%Y%m%d-%H%M%S')}.db"
        dst = sqlite3.connect(str(target))
        try:
            with self.db.lock:
                self.db.conn.backup(dst)
        finally:
            dst.close()
        for old in sorted(self.auto_dir.glob("autosave-*.db"))[:-5]:
            old.unlink(missing_ok=True)
        return target

    def autosaves(self):
        return sorted(({"name": p.name, "size": p.stat().st_size, "modified": p.stat().st_mtime}
                       for p in self.auto_dir.glob("autosave-*.db")), key=lambda x: -x["modified"])

    def recover(self, name):
        p = self.auto_dir / Path(name).name
        if not re.fullmatch(r"autosave-[\d-]+\.db", p.name) or not p.exists():
            raise SessionError("autosave tidak ditemukan")
        src = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            counts = {}
            with self.db.tx() as c:
                for t in reversed(TABLES):
                    c.execute(f"DELETE FROM {t}")
                for t in TABLES:
                    cols = [r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()]
                    rows = src.execute(f"SELECT {','.join(cols)} FROM {t}").fetchall()
                    if rows:
                        c.executemany(f"INSERT INTO {t}({','.join(cols)}) VALUES({','.join('?' * len(cols))})", rows)
                    counts[t] = len(rows)
        finally:
            src.close()
        return counts

    def start_autosave(self):
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="autosave")
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            minutes = self.settings.get("session.autosave_minutes", 5)
            if self._stop.wait(minutes * 60):
                return
            if self.settings.get("session.autosave") and self.db.changes != self._last_changes:
                try:
                    self._last_changes = self.db.changes
                    self.autosave_once()
                except Exception as exc:
                    self.bus.log("error", f"Autosave gagal: {exc}")

    def shutdown(self):
        self._stop.set()
