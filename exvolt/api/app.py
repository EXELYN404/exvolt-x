"""Aplikasi ASGI EXVOLT X (Starlette): REST API, WebSocket real-time, dan file statis."""
from __future__ import annotations

import asyncio
import functools
import hmac
import json
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

from .. import __version__
from ..core.certificate_manager import CertificateManager
from ..core.database import Database
from ..core.event_bus import EventBus
from ..core.guard import TargetGuard
from ..core.http_client import HttpClientError
from ..core.proxy_engine import ProxyEngine, ProxyError
from ..core.scope_manager import ScopeError, ScopeManager
from ..core.session_manager import SessionError, SessionManager
from ..core.settings import BASE_DIR, Settings, is_loopback
from ..modules import comparer, decoder
from ..modules.intruder import IntruderError, IntruderManager
from ..modules.reporting import Reporting
from ..modules.repeater import Repeater, RepeaterError, build_from_raw
from ..modules.scanner import PassiveScanner
from ..modules.sequencer import Sequencer, SequencerError, extract_from_row, analyze as analyze_tokens
from ..utils import httpmsg as hm
from .security import SecurityMiddleware

MAX_JSON = 32 * 1024 * 1024
WEB_DIR = BASE_DIR / "web"


class Ctx:
    """Kontainer semua layanan aplikasi."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.data_dir / "exvolt.db")
        self.bus = EventBus()
        self.scope = ScopeManager(self.db)
        self.guard = TargetGuard(settings, self.scope)
        self.certs = CertificateManager(settings.cert_dir)
        self.proxy = ProxyEngine(settings, self.db, self.bus, self.scope, self.certs)
        self.repeater = Repeater(self.db, settings, self.guard, self.bus)
        self.intruder = IntruderManager(settings, self.guard, self.bus)
        self.scanner = PassiveScanner(self.db, self.bus, settings)
        self.sequencer = Sequencer(self.db, self.bus)
        self.reports = Reporting(settings, self.db, self.scope)
        self.sessions = SessionManager(settings, self.db, self.bus)
        self.proxy.hooks.append(self._scan_hook)
        self.proxy.hooks.append(self.sequencer.hook)

    def _scan_hook(self, hid, row):
        if self.settings.get("scanner.passive_enabled"):
            self.scanner.analyze(row)


# ----------------------------------------------------------------- util
def run(fn, *a, **kw):
    return anyio.to_thread.run_sync(functools.partial(fn, *a, **kw))


async def body_json(request: Request, required=True):
    raw = await request.body()
    if len(raw) > MAX_JSON:
        raise HTTPException(413, "body terlalu besar")
    if not raw:
        if required:
            raise ValueError("body JSON diperlukan")
        return {}
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"JSON tidak valid: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("body harus objek JSON")
    return data


def need(d, key, typ=str, default=None):
    if key not in d:
        if default is not None:
            return default
        raise ValueError(f"field '{key}' wajib")
    v = d[key]
    if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
        raise ValueError(f"field '{key}' harus bertipe {typ.__name__}")
    return v


def api(fn):
    @functools.wraps(fn)
    async def wrapper(request: Request):
        try:
            return await fn(request, request.app.state.ctx)
        except HTTPException:
            raise
        except RepeaterError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403 if str(exc).startswith("request ditolak") else 502)
        except ProxyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        except (ValueError, ScopeError, IntruderError, SequencerError, SessionError, decoder.DecoderError, HttpClientError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except Exception as exc:  # jangan bocorkan trace ke klien, tetapi catat
            request.app.state.ctx.bus.log("error", f"{request.method} {request.url.path}: {type(exc).__name__}: {exc}")
            return JSONResponse({"error": "kesalahan internal server (lihat log)"}, status_code=500)
    return wrapper


def file_response(data, name, ctype):
    safe = re.sub(r"[^\w.-]", "_", name)
    return Response(data, media_type=ctype, headers={"content-disposition": f'attachment; filename="{safe}"'})


def parse_hdrs(s):
    try:
        return json.loads(s or "[]")
    except ValueError:
        return []


def history_detail(r, include_bodies=True):
    rh, qh = parse_hdrs(r["resp_headers"]), parse_hdrs(r["req_headers"])
    rct = r["content_type"] or ""
    req_body = r["req_body"] or b""
    qct = hm.get_header(qh, "content-type") or ""
    raw_req = hm.build_raw_request(r["method"], r["path"], qh, req_body)
    qv = hm.render_body(req_body, qct)
    dec, note = hm.decode_body(rh, r["resp_body"] or b"")
    pv = hm.render_body(dec, rct)
    raw_head = (f"HTTP/1.1 {r['status']} {hm.reason(r['status'])}\r\n" + hm.headers_to_text(rh, "\r\n") + "\r\n\r\n") if r["status"] else ""
    tls = None
    if r["tls"]:
        try:
            tls = json.loads(r["tls"])
        except ValueError:
            pass
    return {
        "id": r["id"], "ts": r["ts"], "scheme": r["scheme"], "host": r["host"], "port": r["port"], "method": r["method"],
        "url": r["url"], "path": r["path"], "status": r["status"], "duration_ms": r["duration_ms"], "error": r["error"],
        "truncated": bool(r["truncated"]), "in_scope": bool(r["in_scope"]), "source": r["source"], "note": r["note"], "tls": tls,
        "request": {"raw": raw_req.decode("utf-8", "replace"), "headers": qh, "body": qv["text"], "binary": qv["binary"],
                    "body_pretty": hm.pretty(qv["text"], qct) if not qv["binary"] else qv["text"], "size": r["req_size"]},
        "response": {"raw_head": raw_head, "headers": rh, "body": pv["text"], "binary": pv["binary"],
                     "body_pretty": hm.pretty(pv["text"], rct) if not pv["binary"] else pv["text"],
                     "size": r["resp_size"], "decoded_size": len(dec), "decode_note": note, "content_type": rct}}


def hist_query(request: Request):
    q = request.query_params
    return {"q": q.get("q"), "body": q.get("body") == "1", "methods": [m for m in q.get("methods", "").split(",") if m],
            "status_class": q.get("status_class"), "host": q.get("host"), "content_type": q.get("content_type"),
            "in_scope": q.get("in_scope") == "1", "source": q.get("source"), "sort": q.get("sort"), "dir": q.get("dir", "desc"),
            "page": q.get("page", 1), "page_size": q.get("page_size", 100)}


# ================================================================ HANDLERS
@api
async def health(request, ctx):
    return JSONResponse({"status": "ok", "app": "EXVOLT X", "publisher": "EXELYN404", "version": __version__,
                         "time": time.time(), "auth_required": bool(ctx.settings.get("server.auth_token"))})


async def auth_status(request):
    ctx = request.app.state.ctx
    mw = request.app.state.security
    import importlib.util as iu
    ws_ok = any(iu.find_spec(m) for m in ("websockets", "wsproto"))
    return JSONResponse({"auth_required": bool(ctx.settings.get("server.auth_token")), "authenticated": mw.authed(request.scope),
                         "realtime": "ws" if ws_ok else "sse"})


async def login(request):
    ctx = request.app.state.ctx
    tok = ctx.settings.get("server.auth_token")
    try:
        data = await body_json(request)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    given = str(data.get("token", ""))
    if not tok or not hmac.compare_digest(given.encode(), tok.encode()):
        await asyncio.sleep(1)  # perlambat tebakan
        return JSONResponse({"error": "token salah"}, status_code=401)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("exvolt_auth", tok, httponly=True, samesite="strict", path="/")
    return resp


@api
async def overview(request, ctx):
    db = ctx.db
    c = lambda sql, *a: db.one(sql, a)["c"]
    since = time.time() - 3600
    timeline = db.q("SELECT CAST((ts-?)/60 AS INTEGER) AS b, COUNT(*) AS n FROM history WHERE ts>=? GROUP BY b", (since, since))
    buckets = [0] * 60
    for r in timeline:
        if 0 <= r["b"] < 60:
            buckets[r["b"]] = r["n"]
    st = {}
    for r in db.q("SELECT status/100 AS k, COUNT(*) AS n FROM history GROUP BY k"):
        st[str(int(r["k"]))] = r["n"]
    return JSONResponse({
        "proxy": ctx.proxy.status(),
        "totals": {"requests": c("SELECT COUNT(*) c FROM history"), "hosts": c("SELECT COUNT(DISTINCT host) c FROM history"),
                   "in_scope": c("SELECT COUNT(*) c FROM history WHERE in_scope=1"), "errors": c("SELECT COUNT(*) c FROM history WHERE error IS NOT NULL"),
                   "findings": c("SELECT COUNT(*) c FROM findings"), "ws_messages": c("SELECT COUNT(*) c FROM ws_messages"),
                   "scope_rules": c("SELECT COUNT(*) c FROM scope_rules WHERE enabled=1"),
                   "bytes": db.one("SELECT COALESCE(SUM(resp_size),0) c FROM history")["c"]},
        "severity": {r["severity"]: r["n"] for r in db.q("SELECT severity, COUNT(*) n FROM findings GROUP BY severity")},
        "status_classes": st,
        "methods": {r["method"]: r["n"] for r in db.q("SELECT method, COUNT(*) n FROM history GROUP BY method ORDER BY n DESC LIMIT 8")},
        "top_hosts": db.q("SELECT host, COUNT(*) n, MAX(in_scope) in_scope, SUM(error IS NOT NULL) errors FROM history GROUP BY host ORDER BY n DESC LIMIT 24"),
        "timeline": buckets, "timeline_start": since,
        "recent_findings": db.q("SELECT id,name,severity,url,ts FROM findings ORDER BY id DESC LIMIT 8"),
        "intruder": [a.summary() for a in ctx.intruder.attacks.values()][-1:]})


# ---- settings
@api
async def settings_get(request, ctx):
    return JSONResponse({"settings": ctx.settings.snapshot(), "paths": {"data": str(ctx.settings.data_dir), "certificates": str(ctx.settings.cert_dir)}})


@api
async def settings_put(request, ctx):
    data = await body_json(request)
    srv = data.get("server", {})
    if "host" in srv or "port" in srv:
        pass  # perubahan host/port server berlaku setelah restart
    try:
        ctx.settings.update(data)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)
    if "intercept" in data.get("proxy", {}):
        ctx.proxy.set_intercept(ctx.settings.get("proxy.intercept"))
    host = ctx.settings.get("server.host")
    if not is_loopback(host) and not ctx.settings.get("server.auth_token"):
        ctx.settings.update({"server": {}})
    return JSONResponse({"settings": ctx.settings.snapshot(), "restart_required": bool({"host", "port"} & set(srv))})


# ---- proxy
@api
async def proxy_status(request, ctx):
    return JSONResponse(ctx.proxy.status() | {"ca": ctx.certs.info(), "ignore_hosts": ctx.settings.get("proxy.ignore_hosts")})


@api
async def proxy_start(request, ctx):
    d = await body_json(request, False)
    await ctx.proxy.start(d.get("host"), d.get("port"))
    return JSONResponse(ctx.proxy.status())


@api
async def proxy_stop(request, ctx):
    await ctx.proxy.stop()
    return JSONResponse(ctx.proxy.status())


@api
async def proxy_intercept(request, ctx):
    d = await body_json(request)
    ctx.proxy.set_intercept(need(d, "enabled", bool))
    ctx.settings.update({"proxy": {"intercept": ctx.proxy.intercept}})
    return JSONResponse(ctx.proxy.status())


@api
async def proxy_queue(request, ctx):
    return JSONResponse({"items": ctx.proxy.queue_list()})


@api
async def proxy_decide(request, ctx):
    qid = request.path_params["id"]
    action = request.path_params["action"]
    if action not in ("forward", "drop"):
        raise HTTPException(404)
    d = await body_json(request, False)
    ok = ctx.proxy.decide(qid, action, d.get("raw") if isinstance(d.get("raw"), str) else None)
    if not ok:
        return JSONResponse({"error": "item tidak ada di antrean (mungkin sudah diproses)"}, status_code=404)
    return JSONResponse({"ok": True})


@api
async def proxy_logs(request, ctx):
    return JSONResponse({"logs": list(ctx.bus.logs)})


@api
async def ca_download(request, ctx):
    fmt = request.query_params.get("format", "pem")
    if fmt == "der":
        return file_response(ctx.certs.ca_der(), "exvolt-ca.der", "application/x-x509-ca-cert")
    return file_response(ctx.certs.ca_pem(), "exvolt-ca.pem", "application/x-pem-file")


@api
async def ca_regen(request, ctx):
    d = await body_json(request)
    if d.get("confirm") is not True:
        raise ValueError("konfirmasi diperlukan: kirim {\"confirm\": true}")
    ctx.certs.regenerate()
    ctx.bus.log("warn", "CA dibuat ulang: instal ulang sertifikat baru di browser")
    return JSONResponse({"ca": ctx.certs.info()})


# ---- history
@api
async def history_list(request, ctx):
    rows, total = await run(ctx.db.search_history, hist_query(request))
    return JSONResponse({"items": rows, "total": total})


@api
async def history_get(request, ctx):
    r = await run(ctx.db.get_history, request.path_params["id"])
    if not r:
        return JSONResponse({"error": "tidak ditemukan"}, status_code=404)
    return JSONResponse(history_detail(r))


@api
async def history_delete_one(request, ctx):
    n = await run(ctx.db.delete_history, [request.path_params["id"]])
    return JSONResponse({"deleted": n}, status_code=200 if n else 404)


@api
async def history_delete_many(request, ctx):
    d = await body_json(request)
    if d.get("all") is True:
        _, n = await run(ctx.db.x, "DELETE FROM history")
        return JSONResponse({"deleted": n})
    ids = d.get("ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids) or len(ids) > 100000:
        raise ValueError("'ids' harus daftar integer tidak kosong")
    return JSONResponse({"deleted": await run(ctx.db.delete_history, ids)})


@api
async def history_export(request, ctx):
    d = await body_json(request)
    ids = d.get("ids")
    if d.get("all") is True:
        ids = [r["id"] for r in ctx.db.q("SELECT id FROM history ORDER BY id LIMIT 5000")]
    if not isinstance(ids, list) or not ids:
        raise ValueError("'ids' wajib")
    fmt = d.get("format", "json")
    if fmt not in ("json", "har"):
        raise ValueError("format harus json atau har")
    data, ctype, ext = await run(ctx.reports.export_entries, ids, fmt)
    return file_response(data, f"exvolt-history.{ext}", ctype)


@api
async def hosts_list(request, ctx):
    return JSONResponse({"hosts": [r["host"] for r in ctx.db.q("SELECT DISTINCT host FROM history ORDER BY host LIMIT 1000")]})


# ---- repeater
@api
async def repeater_send(request, ctx):
    d = await body_json(request)
    if "raw" in d:
        method, url, headers, body = build_from_raw(need(d, "raw"), need(d, "scheme", str, "https"), d.get("host", ""), d.get("port"))
    else:
        method, url = need(d, "method").upper(), need(d, "url")
        headers = hm.text_to_headers(d.get("headers", ""))
        body = str(d.get("body", "")).encode("utf-8")
    timeout = d.get("timeout")
    if timeout is not None and (not isinstance(timeout, (int, float)) or not 1 <= timeout <= 600):
        raise ValueError("timeout harus 1-600 detik")
    resp = await run(ctx.repeater.send, method, url, headers, body, bool(d.get("follow_redirects")), timeout)
    return JSONResponse(resp)


@api
async def repeater_log(request, ctx):
    return JSONResponse({"items": await run(ctx.repeater.log)})


@api
async def repeater_saved(request, ctx):
    if request.method == "GET":
        return JSONResponse({"items": await run(ctx.repeater.saved)})
    d = await body_json(request)
    rid = await run(ctx.repeater.save, need(d, "name"), need(d, "data", dict))
    return JSONResponse({"id": rid}, status_code=201)


@api
async def repeater_saved_delete(request, ctx):
    ok = await run(ctx.repeater.delete_saved, request.path_params["id"])
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


# ---- decoder
@api
async def decoder_run(request, ctx):
    d = await body_json(request)
    direction = request.path_params["direction"]
    out = decoder.transform(need(d, "type"), direction, need(d, "text"))
    return JSONResponse({"output": out})


@api
async def decoder_types(request, ctx):
    return JSONResponse({"types": {k: sorted(v) for k, v in decoder.OPS.items()}})


# ---- comparer
def _item_text(ctx, spec):
    if "history_id" in spec:
        r = ctx.db.get_history(int(spec["history_id"]))
        if not r:
            raise ValueError(f"history #{spec['history_id']} tidak ada")
        det = history_detail(r)
        part = spec.get("part", "response")
        if part == "request":
            return det["request"]["raw"]
        return det["response"]["raw_head"] + det["response"]["body"]
    return need(spec, "text")


@api
async def comparer_compare(request, ctx):
    d = await body_json(request)
    a, b = _item_text(ctx, need(d, "left", dict)), _item_text(ctx, need(d, "right", dict))
    res = await run(comparer.compare, a, b, d.get("mode", "text"), bool(d.get("ignore_whitespace")), bool(d.get("ignore_case")))
    return JSONResponse(res)


@api
async def comparer_export(request, ctx):
    d = await body_json(request)
    a, b = _item_text(ctx, need(d, "left", dict)), _item_text(ctx, need(d, "right", dict))
    res = await run(comparer.compare, a, b, d.get("mode", "text"), bool(d.get("ignore_whitespace")), bool(d.get("ignore_case")))
    if d.get("format") == "json":
        return file_response(json.dumps(res, indent=2, ensure_ascii=False), "perbandingan.json", "application/json")
    return file_response(comparer.export_html(res), "perbandingan.html", "text/html; charset=utf-8")


# ---- scope
@api
async def scope_list(request, ctx):
    return JSONResponse({"rules": ctx.scope.rules(), "enforce": ctx.settings.get("network.enforce_scope")})


@api
async def scope_add(request, ctx):
    d = await body_json(request)
    rule = await run(ctx.scope.add, d)
    return JSONResponse(rule, status_code=201)


@api
async def scope_patch(request, ctx):
    d = await body_json(request)
    ok = ctx.scope.update(request.path_params["id"], need(d, "enabled", bool))
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@api
async def scope_delete(request, ctx):
    ok = ctx.scope.delete(request.path_params["id"])
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@api
async def scope_check(request, ctx):
    d = await body_json(request)
    ok, why = ctx.guard.check(need(d, "url"))
    return JSONResponse({"allowed": ok, "reason": why})


@api
async def scope_export(request, ctx):
    return file_response(json.dumps(ctx.scope.export(), indent=2), "exvolt-scope.json", "application/json")


@api
async def scope_import(request, ctx):
    d = await body_json(request)
    n = ctx.scope.import_rules(need(d, "data", dict), bool(d.get("replace")))
    return JSONResponse({"imported": n})


@api
async def scope_recompute(request, ctx):
    return JSONResponse({"updated": await run(ctx.scope.recompute_history)})


# ---- intruder
@api
async def intruder_start(request, ctx):
    d = await body_json(request)
    att = await run(ctx.intruder.start, d)
    return JSONResponse(att.summary(), status_code=202)


@api
async def intruder_get(request, ctx):
    att = ctx.intruder.get(request.path_params["id"])
    if not att:
        return JSONResponse({"error": "tidak ditemukan"}, status_code=404)
    off = int(request.query_params.get("offset", 0))
    return JSONResponse(att.summary() | {"results": att.results[off:off + 2000], "offset": off})


@api
async def intruder_current(request, ctx):
    items = [a.summary() for a in ctx.intruder.attacks.values()]
    return JSONResponse({"attacks": items, "limits": {"max_requests": ctx.settings.get("intruder.max_requests"),
                                                      "max_concurrency": ctx.settings.get("intruder.max_concurrency"),
                                                      "max_rps": ctx.settings.get("intruder.max_rps")}})


@api
async def intruder_stop(request, ctx):
    ok = ctx.intruder.stop(request.path_params["id"])
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@api
async def intruder_export(request, ctx):
    att = ctx.intruder.get(request.path_params["id"])
    if not att:
        return JSONResponse({"error": "tidak ditemukan"}, status_code=404)
    fmt = request.query_params.get("format", "csv")
    data, ctype = ctx.intruder.export(att, "json" if fmt == "json" else "csv")
    return file_response(data, f"intruder-{att.id}.{'json' if fmt == 'json' else 'csv'}", ctype)


# ---- scanner
@api
async def scanner_findings(request, ctx):
    q = request.query_params
    sev = [s for s in q.get("severity", "").split(",") if s]
    rows = await run(ctx.reports.findings, sev or None, q.get("host"), q.get("in_scope") == "1")
    return JSONResponse({"items": rows, "total": len(rows)})


@api
async def scanner_delete(request, ctx):
    if request.path_params.get("id") is None:
        _, n = ctx.db.x("DELETE FROM findings")
    else:
        _, n = ctx.db.x("DELETE FROM findings WHERE id=?", (request.path_params["id"],))
    return JSONResponse({"deleted": n})


@api
async def scanner_rescan(request, ctx):
    def work():
        n = 0
        for r in ctx.db.iterate("SELECT * FROM history WHERE status>0"):
            n += ctx.scanner.analyze(r)
        return n
    new = await run(work)
    return JSONResponse({"new_findings": new})


@api
async def scanner_tls(request, ctx):
    d = await body_json(request)
    host, port = need(d, "host").strip(), int(d.get("port", 443))
    ok, why = ctx.guard.check(f"https://{host}:{port}/")
    if not ok:
        return JSONResponse({"error": f"probe TLS ditolak: {why}"}, status_code=403)
    try:
        res = await run(ctx.scanner.tls_probe, host, port)
    except Exception as exc:
        return JSONResponse({"error": f"probe TLS gagal: {type(exc).__name__}: {exc}"}, status_code=502)
    return JSONResponse(res)


# ---- sequencer
@api
async def seq_sets(request, ctx):
    return JSONResponse({"sets": ctx.sequencer.sets(), "live": {k: {"kind": v[0], "extract": v[1]} for k, v in ctx.sequencer.live.items()}})


@api
async def seq_live(request, ctx):
    d = await body_json(request)
    if d.get("action") == "stop":
        return JSONResponse({"ok": ctx.sequencer.stop_live(need(d, "name"))})
    ctx.sequencer.start_live(need(d, "name"), need(d, "kind"), need(d, "extract"))
    return JSONResponse({"ok": True}, status_code=201)


@api
async def seq_from_history(request, ctx):
    d = await body_json(request)
    name, kind, ex = need(d, "name"), need(d, "kind"), need(d, "extract")
    ids = d.get("ids")
    if not isinstance(ids, list) or not ids:
        raise ValueError("'ids' wajib")
    ctx.sequencer.create(name, f"{kind}:{ex}")
    n = 0
    for hid in ids[:100000]:
        r = ctx.db.get_history(int(hid))
        if r:
            t = extract_from_row(r, kind, ex)
            if t:
                ctx.sequencer.add_tokens(name, t, hid)
                n += len(t)
    return JSONResponse({"added": n})


@api
async def seq_manual(request, ctx):
    d = await body_json(request)
    name = need(d, "name")
    toks = [t.strip() for t in need(d, "text").splitlines() if t.strip()][:100000]
    ctx.sequencer.create(name, "manual")
    ctx.sequencer.add_tokens(name, toks)
    return JSONResponse({"added": len(toks)})


@api
async def seq_analyze(request, ctx):
    name = request.path_params["name"]
    toks = await run(ctx.sequencer.tokens, name)
    res = await run(analyze_tokens, toks)
    return JSONResponse({"set": name} | res)


@api
async def seq_tokens(request, ctx):
    return JSONResponse({"tokens": ctx.sequencer.tokens(request.path_params["name"], 5000)})


@api
async def seq_delete(request, ctx):
    ctx.sequencer.delete(request.path_params["name"])
    return JSONResponse({"ok": True})


@api
async def seq_export(request, ctx):
    name = request.path_params["name"]
    toks = ctx.sequencer.tokens(name)
    out = {"set": name, "count": len(toks), "tokens": toks}
    try:
        out["analysis"] = analyze_tokens(toks)
    except SequencerError as exc:
        out["analysis_error"] = str(exc)
    return file_response(json.dumps(out, indent=2, ensure_ascii=False), f"sequencer-{re.sub(r'[^\w.-]', '_', name)}.json", "application/json")


# ---- websocket history
@api
async def ws_connections(request, ctx):
    rows = ctx.db.q("SELECT m.conn_id, m.host, m.url, COUNT(*) n, MIN(m.ts) first, MAX(m.ts) last, "
                    "SUM(m.direction='out') out_n, SUM(m.direction='in') in_n FROM ws_messages m GROUP BY m.conn_id ORDER BY m.conn_id DESC LIMIT 500")
    return JSONResponse({"items": rows})


@api
async def ws_messages(request, ctx):
    q = request.query_params
    where, args = [], []
    if q.get("conn_id"):
        where.append("conn_id=?"); args.append(int(q["conn_id"]))
    if q.get("direction") in ("in", "out"):
        where.append("direction=?"); args.append(q["direction"])
    if q.get("kind"):
        where.append("kind=?"); args.append(q["kind"])
    if q.get("q"):
        where.append("instr(CAST(payload AS TEXT), ?)>0"); args.append(q["q"])
    w = (" WHERE " + " AND ".join(where)) if where else ""
    size = max(1, min(int(q.get("page_size", 200)), 1000))
    page = max(1, int(q.get("page", 1)))
    total = ctx.db.one(f"SELECT COUNT(*) c FROM ws_messages{w}", args)["c"]
    rows = ctx.db.q(f"SELECT * FROM ws_messages{w} ORDER BY id DESC LIMIT ? OFFSET ?", args + [size, (page - 1) * size])
    for r in rows:
        v = hm.render_body(r["payload"] or b"")
        r["payload"], r["binary"] = v["text"], v["binary"]
    return JSONResponse({"items": rows, "total": total})


@api
async def ws_export(request, ctx):
    rows = ctx.db.q("SELECT * FROM ws_messages ORDER BY id LIMIT 100000")
    for r in rows:
        r["payload"] = hm.render_body(r["payload"] or b"")["text"]
    return file_response(json.dumps({"format": "exvolt-websocket", "messages": rows}, indent=1, ensure_ascii=False), "exvolt-websocket.json", "application/json")


@api
async def ws_clear(request, ctx):
    _, n = ctx.db.x("DELETE FROM ws_messages")
    return JSONResponse({"deleted": n})


# ---- reports
@api
async def reports_list(request, ctx):
    return JSONResponse({"items": ctx.reports.list()})


@api
async def reports_create(request, ctx):
    d = await body_json(request, False)
    sev = d.get("severities")
    if sev is not None and not (isinstance(sev, list) and all(isinstance(s, str) for s in sev)):
        raise ValueError("'severities' harus daftar string")
    rep = await run(ctx.reports.generate, str(d.get("title") or "Laporan EXVOLT X")[:120], sev, bool(d.get("in_scope_only")))
    return JSONResponse(rep, status_code=201)


@api
async def reports_download(request, ctx):
    kind = request.path_params["kind"]
    if kind not in ("html", "json"):
        raise HTTPException(404)
    p = ctx.reports.file_for(request.path_params["id"], kind)
    if not p:
        return JSONResponse({"error": "tidak ditemukan"}, status_code=404)
    return file_response(p.read_bytes(), p.name, "text/html; charset=utf-8" if kind == "html" else "application/json")


@api
async def reports_delete(request, ctx):
    ok = ctx.reports.delete(request.path_params["id"])
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@api
async def evidence_export(request, ctx):
    data = await run(ctx.reports.export_evidence, request.path_params["id"])
    if data is None:
        return JSONResponse({"error": "temuan tidak ada"}, status_code=404)
    return file_response(data, f"bukti-{request.path_params['id']}.json", "application/json")


# ---- sessions
@api
async def sessions_list(request, ctx):
    return JSONResponse({"items": ctx.sessions.list(), "autosaves": ctx.sessions.autosaves(), "current": ctx.sessions.current,
                         "autosave": ctx.settings.get("session.autosave")})


@api
async def sessions_save(request, ctx):
    d = await body_json(request)
    return JSONResponse(await run(ctx.sessions.save, need(d, "name")), status_code=201)


@api
async def sessions_load(request, ctx):
    d = await body_json(request)
    counts = await run(ctx.sessions.load, need(d, "name"), d.get("replace", True) is not False)
    return JSONResponse({"loaded": counts})


@api
async def sessions_delete(request, ctx):
    ok = ctx.sessions.delete(request.path_params["name"])
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@api
async def sessions_export(request, ctx):
    data = await run(ctx.sessions.export_bytes, "export")
    return file_response(data, f"exvolt-{time.strftime('%Y%m%d-%H%M%S')}.exvolt", "application/gzip")


@api
async def sessions_import(request, ctx):
    data = await request.body()
    if not data:
        raise ValueError("berkas kosong")
    counts = await run(ctx.sessions.import_bytes, data, request.query_params.get("replace") != "0")
    return JSONResponse({"imported": counts})


@api
async def sessions_autosave_now(request, ctx):
    p = await run(ctx.sessions.autosave_once)
    return JSONResponse({"file": p.name}, status_code=201)


@api
async def sessions_recover(request, ctx):
    d = await body_json(request)
    return JSONResponse({"recovered": await run(ctx.sessions.recover, need(d, "name"))})


# ---- realtime
async def ws_events(websocket: WebSocket):
    ctx = websocket.app.state.ctx
    await websocket.accept()
    q = ctx.bus.subscribe()

    async def reader():
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass

    task = asyncio.create_task(reader())
    try:
        await websocket.send_json({"type": "hello", "data": {"version": __version__}})
        while not task.done():
            try:
                ev = await asyncio.wait_for(q.get(), 20)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue
            await websocket.send_json(ev)
    except Exception:
        pass
    finally:
        task.cancel()
        ctx.bus.unsubscribe(q)
        try:
            await websocket.close()
        except Exception:
            pass


async def sse_events(request):
    """Fallback real-time (Server-Sent Events) bila pustaka `websockets` tidak terpasang."""
    ctx = request.app.state.ctx
    q = ctx.bus.subscribe()

    async def gen():
        try:
            yield "retry: 2000\n\n"
            yield f"data: {json.dumps({'type': 'hello', 'data': {'version': __version__}})}\n\n"
            while True:
                if await request.is_disconnected():
                    return
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                    yield f"data: {json.dumps(ev, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            ctx.bus.unsubscribe(q)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"cache-control": "no-store", "x-accel-buffering": "no"})


async def index(request):
    return FileResponse(WEB_DIR / "index.html", headers={"cache-control": "no-cache"})


async def not_found_api(request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail if hasattr(exc, "detail") else "tidak ditemukan"}, status_code=getattr(exc, "status_code", 404))
    return Response("Not found", status_code=404)


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or Settings()
    ctx = Ctx(settings)

    @asynccontextmanager
    async def lifespan(app):
        ctx.bus.bind_loop(asyncio.get_running_loop())
        app.state.ctx = ctx
        ctx.sessions.start_autosave()
        if settings.get("proxy.autostart"):
            try:
                await ctx.proxy.start()
            except ProxyError as exc:
                ctx.bus.log("error", f"Autostart proxy gagal: {exc}")
        yield
        await ctx.proxy.stop()
        ctx.sessions.shutdown()
        try:
            ctx.db.close()
        except Exception:
            pass

    G, P, D = ["GET"], ["POST"], ["DELETE"]
    r = lambda path, fn, m=G: Route(path, fn, methods=m)
    routes = [
        r("/api/health", health), r("/api/auth/status", auth_status), r("/api/login", login, P),
        r("/api/overview", overview),
        r("/api/settings", settings_get), r("/api/settings", settings_put, ["PUT"]),
        r("/api/proxy/status", proxy_status), r("/api/proxy/start", proxy_start, P), r("/api/proxy/stop", proxy_stop, P),
        r("/api/proxy/intercept", proxy_intercept, P), r("/api/proxy/queue", proxy_queue),
        r("/api/proxy/queue/{id:int}/{action}", proxy_decide, P), r("/api/proxy/logs", proxy_logs),
        r("/api/proxy/ca", ca_download), r("/api/proxy/ca/regenerate", ca_regen, P),
        r("/api/history", history_list), r("/api/history/hosts", hosts_list), r("/api/history/delete", history_delete_many, P),
        r("/api/history/export", history_export, P), r("/api/history/{id:int}", history_get),
        r("/api/history/{id:int}", history_delete_one, D),
        r("/api/repeater/send", repeater_send, P), r("/api/repeater/log", repeater_log),
        r("/api/repeater/saved", repeater_saved, ["GET", "POST"]), r("/api/repeater/saved/{id:int}", repeater_saved_delete, D),
        r("/api/decoder/types", decoder_types), r("/api/decoder/{direction}", decoder_run, P),
        r("/api/comparer/compare", comparer_compare, P), r("/api/comparer/export", comparer_export, P),
        r("/api/scope", scope_list), r("/api/scope", scope_add, P), r("/api/scope/check", scope_check, P),
        r("/api/scope/export", scope_export), r("/api/scope/import", scope_import, P),
        r("/api/scope/recompute", scope_recompute, P),
        r("/api/scope/{id:int}", scope_patch, ["PATCH"]), r("/api/scope/{id:int}", scope_delete, D),
        r("/api/intruder", intruder_current), r("/api/intruder/start", intruder_start, P),
        r("/api/intruder/{id:int}", intruder_get), r("/api/intruder/{id:int}/stop", intruder_stop, P),
        r("/api/intruder/{id:int}/export", intruder_export),
        r("/api/scanner/findings", scanner_findings), r("/api/scanner/findings", scanner_delete, D),
        r("/api/scanner/findings/{id:int}", scanner_delete, D), r("/api/scanner/rescan", scanner_rescan, P),
        r("/api/scanner/tls", scanner_tls, P),
        r("/api/sequencer/sets", seq_sets), r("/api/sequencer/live", seq_live, P),
        r("/api/sequencer/from-history", seq_from_history, P), r("/api/sequencer/manual", seq_manual, P),
        r("/api/sequencer/{name}/analyze", seq_analyze), r("/api/sequencer/{name}/tokens", seq_tokens),
        r("/api/sequencer/{name}/export", seq_export), r("/api/sequencer/{name}", seq_delete, D),
        r("/api/websocket/connections", ws_connections), r("/api/websocket/messages", ws_messages),
        r("/api/websocket/export", ws_export), r("/api/websocket/messages", ws_clear, D),
        r("/api/reports", reports_list), r("/api/reports", reports_create, P),
        r("/api/reports/{id:int}/{kind}", reports_download), r("/api/reports/{id:int}", reports_delete, D),
        r("/api/evidence/{id:int}", evidence_export),
        r("/api/sessions", sessions_list), r("/api/sessions/save", sessions_save, P), r("/api/sessions/load", sessions_load, P),
        r("/api/sessions/export", sessions_export), r("/api/sessions/import", sessions_import, P),
        r("/api/sessions/autosave", sessions_autosave_now, P), r("/api/sessions/recover", sessions_recover, P),
        r("/api/sessions/{name}", sessions_delete, D),
        WebSocketRoute("/api/ws", ws_events), Route("/api/events", sse_events),
        Route("/", index),
        Mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets"),
        Route("/favicon.svg", lambda req: FileResponse(WEB_DIR / "favicon.svg")),
    ]
    app = Starlette(routes=routes, lifespan=lifespan, exception_handlers={HTTPException: not_found_api})
    app.state.ctx = ctx
    sec = SecurityMiddleware(app, settings)
    app.state.security = sec
    app.add_middleware(SecurityMiddleware, settings=settings)
    return app
