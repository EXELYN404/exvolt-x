"""Pelaporan: HTML/JSON dari temuan nyata, ekspor request/response dan bukti."""
from __future__ import annotations

import base64
import datetime as dt
import html
import json
import re
import time

from .. import __version__
from ..utils import httpmsg as hm

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Reporting:
    def __init__(self, settings, db, scope):
        self.settings, self.db, self.scope = settings, db, scope
        self.dir = settings.data_dir / "reports"
        self.dir.mkdir(parents=True, exist_ok=True)

    def findings(self, severities=None, host=None, in_scope_only=False):
        rows = self.db.q("SELECT * FROM findings")
        if severities:
            rows = [r for r in rows if r["severity"] in severities]
        if host:
            rows = [r for r in rows if r["host"] == host]
        if in_scope_only:
            rows = [r for r in rows if self.scope.in_scope(r["url"])]
        rows.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["name"], r["url"]))
        return rows

    def build(self, title, severities=None, in_scope_only=False):
        f = self.findings(severities, None, in_scope_only)
        counts = {s: 0 for s in SEV_ORDER}
        for r in f:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        return {
            "title": title, "generator": f"EXVOLT X {__version__} (EXELYN404)", "generated": time.time(),
            "generated_iso": iso(time.time()),
            "scope": {"rules": [{k: r[k] for k in ("action", "type", "value", "enabled")} for r in self.scope.rules()]},
            "totals": {"findings": len(f), "by_severity": counts,
                       "requests_captured": self.db.one("SELECT COUNT(*) c FROM history")["c"]},
            "findings": [{k: r[k] for k in ("id", "name", "severity", "confidence", "description", "evidence", "url",
                                            "remediation", "history_id")} | {"detected": iso(r["ts"])} for r in f],
        }

    def render_html(self, rep):
        e = html.escape
        css = ("body{font:14px/1.5 system-ui,sans-serif;background:#0f1412;color:#d7e0dc;margin:0;padding:32px;max-width:980px;margin:auto}"
               "h1{color:#34d399}h2{border-bottom:1px solid #2a3531;padding-bottom:4px}.f{border:1px solid #2a3531;border-left:4px solid #888;"
               "border-radius:6px;padding:12px 16px;margin:12px 0;background:#161d1a}.critical{border-left-color:#ef4444}.high{border-left-color:#f97316}"
               ".medium{border-left-color:#eab308}.low{border-left-color:#38bdf8}.info{border-left-color:#94a3b8}code,pre{background:#0b100e;border-radius:4px;"
               "padding:2px 6px;font:12px ui-monospace,monospace;white-space:pre-wrap;word-break:break-all}.b{display:inline-block;padding:1px 8px;border-radius:10px;"
               "background:#233;font-size:12px;margin-right:6px}table{border-collapse:collapse}td,th{border:1px solid #2a3531;padding:4px 10px}")
        by = rep["totals"]["by_severity"]
        sc = "".join(f"<tr><td>{e(r['action'])}</td><td>{e(r['type'])}</td><td><code>{e(r['value'])}</code></td><td>{'ya' if r['enabled'] else 'tidak'}</td></tr>"
                     for r in rep["scope"]["rules"]) or "<tr><td colspan=4>Scope kosong</td></tr>"
        items = []
        for f in rep["findings"]:
            items.append(
                f"<div class='f {e(f['severity'])}'><h3>{e(f['name'])}</h3><span class='b'>{e(f['severity'].upper())}</span>"
                f"<span class='b'>keyakinan: {e(f['confidence'])}</span><span class='b'>{e(f['detected'])}</span>"
                f"<p>{e(f['description'])}</p><p><b>URL terdampak:</b> <code>{e(f['url'])}</code></p>"
                f"<p><b>Bukti:</b></p><pre>{e(f['evidence'])}</pre><p><b>Perbaikan:</b> {e(f['remediation'])}</p></div>")
        summary = " · ".join(f"{k}: {v}" for k, v in by.items())
        return (f"<!doctype html><html lang='id'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                f"<title>{e(rep['title'])}</title><style>{css}</style><body><h1>{e(rep['title'])}</h1>"
                f"<p>Dibuat: {e(rep['generated_iso'])} oleh {e(rep['generator'])}</p>"
                f"<h2>Ringkasan</h2><p>Total temuan: <b>{rep['totals']['findings']}</b> ({e(summary)}). "
                f"Request tertangkap: {rep['totals']['requests_captured']}.</p><h2>Scope</h2>"
                f"<table><tr><th>Aksi</th><th>Tipe</th><th>Nilai</th><th>Aktif</th></tr>{sc}</table>"
                f"<h2>Temuan</h2>{''.join(items) or '<p>Tidak ada temuan tercatat.</p>'}</body></html>")

    def generate(self, title, severities=None, in_scope_only=False):
        rep = self.build(title or "Laporan EXVOLT X", severities, in_scope_only)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^\w-]+", "_", rep["title"])[:40].strip("_") or "laporan"
        hf, jf = f"{slug}-{stamp}.html", f"{slug}-{stamp}.json"
        (self.dir / hf).write_text(self.render_html(rep), encoding="utf-8")
        (self.dir / jf).write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        rid, _ = self.db.x("INSERT INTO reports(title,ts,summary,html_file,json_file) VALUES(?,?,?,?,?)",
                           (rep["title"], rep["generated"], json.dumps(rep["totals"]), hf, jf))
        return {"id": rid, "title": rep["title"], "ts": rep["generated"], "summary": rep["totals"], "html_file": hf, "json_file": jf}

    def list(self):
        return [{"id": r["id"], "title": r["title"], "ts": r["ts"], "summary": json.loads(r["summary"] or "{}"),
                 "html_file": r["html_file"], "json_file": r["json_file"]}
                for r in self.db.q("SELECT * FROM reports ORDER BY id DESC")]

    def file_for(self, rid, kind):
        r = self.db.one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return None
        name = r["html_file"] if kind == "html" else r["json_file"]
        p = (self.dir / name).resolve()
        return p if p.parent == self.dir.resolve() and p.exists() else None

    def delete(self, rid):
        r = self.db.one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return False
        for n in (r["html_file"], r["json_file"]):
            (self.dir / n).unlink(missing_ok=True)
        self.db.x("DELETE FROM reports WHERE id=?", (rid,))
        return True

    # --------------------------------------------------- ekspor traffic
    def export_entries(self, ids, fmt="json"):
        out = []
        for hid in ids[:5000]:
            r = self.db.get_history(hid)
            if not r:
                continue
            rh, qh = json.loads(r["resp_headers"] or "[]"), json.loads(r["req_headers"] or "[]")
            body, _ = hm.decode_body(rh, r["resp_body"] or b"")
            out.append({"id": r["id"], "time": iso(r["ts"]), "method": r["method"], "url": r["url"], "status": r["status"],
                        "duration_ms": r["duration_ms"], "error": r["error"],
                        "request": {"headers": qh, "body_b64": base64.b64encode(r["req_body"] or b"").decode()},
                        "response": {"headers": rh, "body_b64": base64.b64encode(r["resp_body"] or b"").decode(),
                                     "decoded_text": hm.render_body(body, r["content_type"] or "")["text"][:200000]}})
        if fmt == "har":
            entries = []
            for o in out:
                entries.append({
                    "startedDateTime": o["time"].replace(" UTC", "Z").replace(" ", "T"), "time": o["duration_ms"],
                    "request": {"method": o["method"], "url": o["url"], "httpVersion": "HTTP/1.1", "cookies": [], "queryString": [],
                                "headers": [{"name": k, "value": v} for k, v in o["request"]["headers"]], "headersSize": -1,
                                "bodySize": len(base64.b64decode(o["request"]["body_b64"]))},
                    "response": {"status": o["status"], "statusText": hm.reason(o["status"]), "httpVersion": "HTTP/1.1", "cookies": [],
                                 "headers": [{"name": k, "value": v} for k, v in o["response"]["headers"]],
                                 "content": {"size": len(base64.b64decode(o["response"]["body_b64"])), "mimeType": hm.get_header(o["response"]["headers"], "content-type") or "",
                                             "text": o["response"]["body_b64"], "encoding": "base64"}, "redirectURL": "", "headersSize": -1, "bodySize": -1},
                    "cache": {}, "timings": {"send": 0, "wait": o["duration_ms"] or 0, "receive": 0}})
            return json.dumps({"log": {"version": "1.2", "creator": {"name": "EXVOLT X", "version": __version__}, "entries": entries}},
                              indent=1), "application/json", "har"
        return json.dumps({"format": "exvolt-traffic", "entries": out}, indent=1, ensure_ascii=False), "application/json", "json"

    def export_evidence(self, finding_id):
        f = self.db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
        if not f:
            return None
        ev = {"finding": f}
        if f.get("history_id"):
            data = json.loads(self.export_entries([f["history_id"]])[0])
            ev["transaction"] = data["entries"][0] if data["entries"] else None
        return json.dumps(ev, indent=2, ensure_ascii=False, default=str)
