"""Lapisan SQLite: riwayat, temuan, WebSocket, scope, token, laporan."""
from __future__ import annotations

import contextlib
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, scheme TEXT, host TEXT, port INTEGER,
  method TEXT, url TEXT, path TEXT, status INTEGER DEFAULT 0, req_headers TEXT, req_body BLOB,
  resp_headers TEXT, resp_body BLOB, content_type TEXT, resp_size INTEGER DEFAULT 0,
  req_size INTEGER DEFAULT 0, duration_ms REAL DEFAULT 0, tls TEXT, error TEXT,
  truncated INTEGER DEFAULT 0, in_scope INTEGER DEFAULT 0, source TEXT DEFAULT 'proxy', note TEXT);
CREATE INDEX IF NOT EXISTS ix_hist_host ON history(host);
CREATE INDEX IF NOT EXISTS ix_hist_ts ON history(ts);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, name TEXT, severity TEXT, confidence TEXT,
  description TEXT, evidence TEXT, url TEXT, host TEXT, remediation TEXT, history_id INTEGER,
  fkey TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS ws_messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, conn_id INTEGER, ts REAL, direction TEXT, opcode INTEGER,
  kind TEXT, payload BLOB, length INTEGER, host TEXT, url TEXT);
CREATE INDEX IF NOT EXISTS ix_ws_conn ON ws_messages(conn_id);
CREATE TABLE IF NOT EXISTS scope_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, type TEXT, value TEXT, enabled INTEGER DEFAULT 1, note TEXT);
CREATE TABLE IF NOT EXISTS token_sets(name TEXT PRIMARY KEY, source TEXT, created REAL);
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT, set_name TEXT, value TEXT, ts REAL, history_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_tok_set ON tokens(set_name);
CREATE TABLE IF NOT EXISTS saved_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ts REAL, data TEXT);
CREATE TABLE IF NOT EXISTS repeater_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, data TEXT);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, ts REAL, summary TEXT, html_file TEXT, json_file TEXT);
"""

SORTABLE = {"id", "ts", "host", "method", "url", "status", "content_type", "resp_size", "duration_ms"}
LIST_COLS = ("id, ts, scheme, host, port, method, url, path, status, content_type, resp_size, req_size, "
             "duration_ms, tls, error, truncated, in_scope, source, note")


def _like(s: str) -> str:
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.changes = 0  # penghitung perubahan untuk autosave
        self._inserts = 0

    def close(self):
        with self.lock:
            self.conn.close()

    # ---- primitif
    def q(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.q(sql, params)
        return rows[0] if rows else None

    def x(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.changes += 1
            return cur.lastrowid, cur.rowcount

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")
                self.changes += 1

    def iterate(self, sql, params=(), batch=200):
        """Generator baris dict secara bertahap (hemat memori)."""
        with self.lock:
            cur = self.conn.execute(sql, params)
        while True:
            with self.lock:
                rows = cur.fetchmany(batch)
            if not rows:
                return
            for r in rows:
                yield dict(r)

    # ---- history
    def add_history(self, e: dict, max_entries=50000) -> int:
        cols = ("ts", "scheme", "host", "port", "method", "url", "path", "status", "req_headers", "req_body",
                "resp_headers", "resp_body", "content_type", "resp_size", "req_size", "duration_ms", "tls",
                "error", "truncated", "in_scope", "source", "note")
        vals = [e.get(c) for c in cols]
        vals[0] = vals[0] or time.time()
        rid, _ = self.x(f"INSERT INTO history({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)
        self._inserts += 1
        if self._inserts % 100 == 0:
            self.trim_history(max_entries)
        return rid

    def trim_history(self, max_entries):
        row = self.one("SELECT COUNT(*) c, MAX(id) m FROM history")
        if row and row["c"] > max_entries:
            cutoff = self.one("SELECT id FROM history ORDER BY id DESC LIMIT 1 OFFSET ?", (max_entries,))
            if cutoff:
                self.x("DELETE FROM history WHERE id<=?", (cutoff["id"],))

    def get_history(self, hid):
        return self.one("SELECT * FROM history WHERE id=?", (hid,))

    def search_history(self, p: dict):
        where, args = [], []
        if p.get("q"):
            like = _like(p["q"])
            parts = ["url LIKE ? ESCAPE '\\'", "host LIKE ? ESCAPE '\\'", "method LIKE ? ESCAPE '\\'",
                     "CAST(status AS TEXT) LIKE ? ESCAPE '\\'"]
            args += [like] * 4
            if p.get("body"):
                parts += ["instr(CAST(req_body AS TEXT), ?)>0", "instr(CAST(resp_body AS TEXT), ?)>0"]
                args += [p["q"], p["q"]]
            where.append("(" + " OR ".join(parts) + ")")
        if p.get("methods"):
            ms = [m.upper() for m in p["methods"]][:20]
            where.append(f"method IN ({','.join('?' * len(ms))})")
            args += ms
        if p.get("status_class") not in (None, ""):
            sc = int(p["status_class"])
            if sc == 0:
                where.append("status=0")
            else:
                where.append("status>=? AND status<?")
                args += [sc * 100, sc * 100 + 100]
        if p.get("host"):
            where.append("host=?")
            args.append(p["host"])
        if p.get("content_type"):
            where.append("content_type LIKE ? ESCAPE '\\'")
            args.append(_like(p["content_type"]))
        if p.get("in_scope"):
            where.append("in_scope=1")
        if p.get("source"):
            where.append("source=?")
            args.append(p["source"])
        w = (" WHERE " + " AND ".join(where)) if where else ""
        sort = p.get("sort") if p.get("sort") in SORTABLE else "id"
        direction = "ASC" if str(p.get("dir", "desc")).lower() == "asc" else "DESC"
        size = max(1, min(int(p.get("page_size", 100)), 500))
        page = max(1, int(p.get("page", 1)))
        total = self.one(f"SELECT COUNT(*) c FROM history{w}", args)["c"]
        rows = self.q(f"SELECT {LIST_COLS} FROM history{w} ORDER BY {sort} {direction} LIMIT ? OFFSET ?",
                      args + [size, (page - 1) * size])
        return rows, total

    def delete_history(self, ids):
        n = 0
        with self.tx() as c:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                n += c.execute(f"DELETE FROM history WHERE id IN ({','.join('?' * len(chunk))})", chunk).rowcount
        return n
