"""Mesin proxy HTTP/HTTPS nyata (asyncio): intersepsi, MITM TLS, riwayat, sniffing WebSocket."""
from __future__ import annotations

import asyncio
import fnmatch
import html
import json
import time
from urllib.parse import urlsplit

from ..utils import httpmsg as hm
from .settings import is_loopback

MAX_REQ_BODY = 64 * 1024 * 1024
WS_PAYLOAD_CAP = 1024 * 1024
WS_MAX_ROWS = 200_000


class ProxyError(Exception):
    pass


# ------------------------------------------------------------------ parsing
async def read_head(reader):
    return await reader.readuntil(b"\r\n\r\n")


def parse_head(data: bytes):
    lines = data[:-4].decode("latin-1").split("\r\n")
    headers = []
    for ln in lines[1:]:
        if not ln:
            continue
        if ":" not in ln:
            raise ProxyError("header tidak valid")
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return lines[0], headers


async def _consume_trailers(reader):
    while True:
        t = await reader.readline()
        if t in (b"\r\n", b"\n", b""):
            return


async def iter_chunked(reader):
    while True:
        line = await reader.readline()
        if not line:
            raise ProxyError("koneksi terputus saat membaca chunked")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError as exc:
            raise ProxyError("ukuran chunk tidak valid") from exc
        if size == 0:
            await _consume_trailers(reader)
            return
        data = await reader.readexactly(size)
        await reader.readexactly(2)
        yield data


async def iter_fixed(reader, n):
    while n > 0:
        d = await reader.read(min(65536, n))
        if not d:
            raise ProxyError("upstream menutup koneksi sebelum body selesai")
        n -= len(d)
        yield d


async def iter_eof(reader):
    while True:
        d = await reader.read(65536)
        if not d:
            return
        yield d


async def read_request_body(reader, headers):
    te = (hm.get_header(headers, "transfer-encoding") or "").lower()
    out = bytearray()
    if "chunked" in te:
        async for c in iter_chunked(reader):
            out += c
            if len(out) > MAX_REQ_BODY:
                raise ProxyError("body request terlalu besar")
        return bytes(out)
    cl = hm.get_header(headers, "content-length")
    if cl:
        if not cl.isdigit():
            raise ProxyError("Content-Length tidak valid")
        n = int(cl)
        if n > MAX_REQ_BODY:
            raise ProxyError("body request terlalu besar")
        return await reader.readexactly(n) if n else b""
    return b""


def split_hostport(target, default):
    t = target.strip()
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default
    if t.count(":") == 1:
        h, p = t.split(":")
        if p.isdigit():
            return h, int(p)
    return t, default


# --------------------------------------------------------- WebSocket sniffer
class WsParser:
    """Parser frame WebSocket pasif (tidak mengubah data yang diteruskan)."""

    def __init__(self):
        self.buf = bytearray()
        self.frag_op, self.frag = None, bytearray()

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            b = self.buf
            if len(b) < 2:
                break
            fin, op = bool(b[0] & 0x80), b[0] & 0x0F
            masked, ln, pos = bool(b[1] & 0x80), b[1] & 0x7F, 2
            if ln == 126:
                if len(b) < 4:
                    break
                ln, pos = int.from_bytes(b[2:4], "big"), 4
            elif ln == 127:
                if len(b) < 10:
                    break
                ln, pos = int.from_bytes(b[2:10], "big"), 10
            key = b""
            if masked:
                if len(b) < pos + 4:
                    break
                key, pos = bytes(b[pos:pos + 4]), pos + 4
            if len(b) < pos + ln:
                if ln > 64 * 1024 * 1024:
                    raise ProxyError("frame WebSocket terlalu besar")
                break
            payload = bytes(b[pos:pos + ln])
            del self.buf[:pos + ln]
            if masked:
                payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
            if op >= 8:
                out.append((op, payload))
                continue
            if op != 0:
                self.frag_op, self.frag = op, bytearray()
            if len(self.frag) < WS_PAYLOAD_CAP:
                self.frag += payload
            if fin:
                out.append((self.frag_op or op, bytes(self.frag)))
                self.frag_op, self.frag = None, bytearray()
        return out


WS_KINDS = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}


class Held:
    def __init__(self, hid, scheme, host, port, raw, encoding, loop):
        self.id, self.scheme, self.host, self.port = hid, scheme, host, port
        self.raw, self.encoding, self.ts = raw, encoding, time.time()
        self.future = loop.create_future()


class ProxyEngine:
    def __init__(self, settings, db, bus, scope, certs):
        self.settings, self.db, self.bus, self.scope, self.certs = settings, db, bus, scope, certs
        self.server = None
        self.host = self.port = None
        self.intercept = bool(settings.get("proxy.intercept"))
        self.queue: dict[int, Held] = {}
        self._qid = 0
        self.conns: set = set()
        self.hooks = []  # callable(history_id, row_dict) -> dijalankan di thread
        self.stats = {"connections": 0, "requests": 0, "errors": 0, "started": None}

    # ------------------------------------------------------------- status
    @property
    def running(self):
        return self.server is not None

    def status(self):
        return {"running": self.running, "host": self.host, "port": self.port, "intercept": self.intercept,
                "queue": len(self.queue), "mitm_https": self.settings.get("proxy.mitm_https"),
                "stats": dict(self.stats)}

    def log(self, level, msg):
        self.bus.log(level, msg)

    # -------------------------------------------------------- start / stop
    async def start(self, host=None, port=None):
        if self.running:
            raise ProxyError("proxy sudah berjalan")
        host = host or self.settings.get("proxy.host")
        port = self.settings.get("proxy.port") if port is None else port
        if not is_loopback(host) and not self.settings.get("proxy.allow_remote"):
            raise ProxyError("binding non-localhost ditolak: aktifkan proxy.allow_remote secara eksplisit "
                             "(proxy tidak memiliki autentikasi, siapa pun di jaringan dapat memakainya)")
        try:
            self.server = await asyncio.start_server(self._on_client, host, port, limit=2 ** 20)
        except OSError as exc:
            raise ProxyError(f"tidak dapat listen di {host}:{port}: {exc.strerror or exc}") from exc
        sock = self.server.sockets[0].getsockname()
        self.host, self.port = sock[0], sock[1]
        self.stats = {"connections": 0, "requests": 0, "errors": 0, "started": time.time()}
        self.log("info", f"Proxy listen di {self.host}:{self.port}")
        self.bus.publish("proxy_status", self.status())

    async def stop(self):
        if not self.running:
            return
        srv, self.server = self.server, None
        srv.close()
        for h in list(self.queue.values()):
            if not h.future.done():
                h.future.set_result(("drop", None))
        for w in list(self.conns):
            try:
                w.close()
            except Exception:
                pass
        try:
            await asyncio.wait_for(srv.wait_closed(), 5)
        except Exception:
            pass
        self.host = self.port = None
        self.log("info", "Proxy dihentikan")
        self.bus.publish("proxy_status", self.status())

    # ---------------------------------------------------------- intercept
    def set_intercept(self, enabled: bool):
        self.intercept = bool(enabled)
        if not enabled:
            for h in list(self.queue.values()):
                if not h.future.done():
                    h.future.set_result(("forward", None))
            if self.queue:
                self.log("warn", "Intercept dimatikan: item antrean diteruskan tanpa perubahan")
        self.bus.publish("proxy_status", self.status())

    def queue_list(self):
        return [{"id": h.id, "ts": h.ts, "scheme": h.scheme, "host": h.host, "port": h.port,
                 "encoding": h.encoding, "raw": h.raw.decode(h.encoding, "replace")} for h in self.queue.values()]

    def decide(self, qid, action, raw_text=None):
        h = self.queue.get(qid)
        if not h or h.future.done():
            return False
        raw = None
        if action == "forward" and raw_text is not None:
            try:
                raw = raw_text.encode(h.encoding)
            except UnicodeEncodeError:
                raw = raw_text.encode("utf-8")
            try:
                hm.parse_raw_request(raw)
            except ValueError as exc:
                raise ProxyError(f"request hasil edit tidak valid: {exc}") from exc
        h.future.set_result((action, raw))
        return True

    # ------------------------------------------------------------- client
    async def _on_client(self, reader, writer):
        self.conns.add(writer)
        self.stats["connections"] += 1
        try:
            await self._serve(reader, writer)
        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception as exc:
            self.stats["errors"] += 1
            self.log("error", f"Kesalahan koneksi klien: {type(exc).__name__}: {exc}")
        finally:
            self.conns.discard(writer)
            try:
                writer.close()
            except Exception:
                pass

    async def _respond(self, writer, code, body: bytes, ctype="text/plain; charset=utf-8", extra=()):
        head = f"HTTP/1.1 {code} {hm.reason(code)}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in extra) + "\r\n"
        writer.write(head.encode("latin-1") + body)
        await writer.drain()

    async def _serve(self, reader, writer, scheme=None, host=None, port=None):
        while True:
            try:
                head = await asyncio.wait_for(read_head(reader), 120)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, asyncio.LimitOverrunError):
                return
            try:
                first, headers = parse_head(head)
                parts = first.split(" ")
                if len(parts) != 3:
                    raise ProxyError("request line tidak valid")
                method, target, version = parts
            except ProxyError as exc:
                await self._respond(writer, 400, str(exc).encode())
                return
            if method == "CONNECT" and scheme is None:
                await self._connect(reader, writer, target)
                return
            if scheme is None:
                if target.startswith(("http://", "https://")):
                    u = urlsplit(target)
                    sch, h, p = u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)
                    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                else:
                    await self._info_page(writer, target)
                    return
            else:
                sch, h, p, path = scheme, host, port, target
            try:
                if (hm.get_header(headers, "expect") or "").lower() == "100-continue":
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                    await writer.drain()
                body = await read_request_body(reader, headers)
            except (ProxyError, asyncio.IncompleteReadError) as exc:
                await self._respond(writer, 400, f"body request tidak valid: {exc}".encode())
                return
            keep = await self._transaction(reader, writer, sch, h, p, method, path, version, headers, body)
            if not keep:
                return

    async def _info_page(self, writer, target):
        path = target.split("?")[0]
        if path == "/ca.pem":
            await self._respond(writer, 200, self.certs.ca_pem(), "application/x-pem-file",
                                [("Content-Disposition", 'attachment; filename="exvolt-ca.pem"')])
        elif path == "/ca.der":
            await self._respond(writer, 200, self.certs.ca_der(), "application/x-x509-ca-cert",
                                [("Content-Disposition", 'attachment; filename="exvolt-ca.der"')])
        else:
            page = ("<!doctype html><meta charset=utf-8><title>EXVOLT X</title><h1>EXVOLT X Proxy</h1>"
                    "<p>Proxy aktif. Unduh sertifikat CA: <a href='/ca.pem'>PEM</a> | <a href='/ca.der'>DER</a></p>")
            await self._respond(writer, 200, page.encode(), "text/html; charset=utf-8")

    # ------------------------------------------------------------ CONNECT
    def _ignored(self, host):
        return any(fnmatch.fnmatch(host.lower(), p.lower()) for p in self.settings.get("proxy.ignore_hosts", []))

    async def _connect(self, reader, writer, target):
        host, port = split_hostport(target, 443)
        timeout = self.settings.get("proxy.upstream_timeout")
        if self._ignored(host) or not self.settings.get("proxy.mitm_https"):
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            except Exception as exc:
                await self._respond(writer, 502, f"tidak dapat terhubung ke {host}:{port}: {exc}".encode())
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            self.log("info", f"Tunnel langsung (tanpa intersepsi) ke {host}:{port}")

            async def pump(r, w):
                try:
                    while True:
                        d = await r.read(65536)
                        if not d:
                            break
                        w.write(d)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass
            await asyncio.gather(pump(reader, uw), pump(ur, writer))
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        try:
            ctx = self.certs.server_context(host)
            await writer.start_tls(ctx, ssl_handshake_timeout=15)
        except Exception as exc:
            self.stats["errors"] += 1
            self.log("warn", f"Handshake TLS dengan klien gagal untuk {host}: {type(exc).__name__} "
                             f"(CA EXVOLT X belum dipercaya oleh klien?)")
            return
        await self._serve(reader, writer, "https", host, port)

    # --------------------------------------------------------- transaksi
    async def _transaction(self, creader, cwriter, scheme, host, port, method, path, version, headers, body):
        self.stats["requests"] += 1
        default = 443 if scheme == "https" else 80
        hostpart = f"[{host}]" if ":" in host else host
        url = f"{scheme}://{hostpart}{'' if port == default else f':{port}'}{path}"
        in_scope = self.scope.in_scope(url)
        record = not (self.settings.get("proxy.only_in_scope_history") and not in_scope)
        client_keepalive = version.upper() == "HTTP/1.1" and \
            "close" not in (hm.get_header(headers, "connection") or "").lower()
        t0 = time.perf_counter()
        entry = {"ts": time.time(), "scheme": scheme, "host": host, "port": port, "method": method, "url": url,
                 "path": path, "status": 0, "content_type": "", "resp_size": 0, "req_size": len(body),
                 "in_scope": 1 if in_scope else 0, "source": "proxy", "error": None, "truncated": 0}
        # ---- intercept
        if self.intercept and (in_scope or not self.settings.get("proxy.intercept_only_in_scope")):
            raw = hm.build_raw_request(method, path, headers, body, version)
            try:
                raw.decode("utf-8")
                enc = "utf-8"
            except UnicodeDecodeError:
                enc = "latin-1"
            self._qid += 1
            held = Held(self._qid, scheme, host, port, raw, enc, asyncio.get_running_loop())
            self.queue[held.id] = held
            self.bus.publish("intercept", {"queue": len(self.queue)})
            try:
                action, new_raw = await asyncio.wait_for(held.future, self.settings.get("proxy.intercept_timeout"))
            except asyncio.TimeoutError:
                action, new_raw = "drop", None
                self.log("warn", f"Item intercept #{held.id} kedaluwarsa dan dibuang")
            finally:
                self.queue.pop(held.id, None)
                self.bus.publish("intercept", {"queue": len(self.queue)})
            if action == "drop":
                entry.update(req_headers=json.dumps(headers), req_body=body[:self.settings.get("proxy.max_body_bytes")],
                             resp_headers="[]", error="dibuang (drop) oleh pengguna", duration_ms=0)
                try:
                    await self._respond(cwriter, 403, "Request dibuang oleh EXVOLT X".encode())
                except Exception:
                    pass
                if record:
                    self._store(entry)
                return False
            if new_raw is not None:
                p = hm.parse_raw_request(new_raw)
                method, path, headers, body = p["method"], p["target"], p["headers"], p["body"]
                url = f"{scheme}://{hostpart}{'' if port == default else f':{port}'}{path}"
                entry.update(method=method, path=path, url=url, req_size=len(body),
                             in_scope=1 if self.scope.in_scope(url) else 0)
        cap = self.settings.get("proxy.max_body_bytes")
        entry["req_headers"], entry["req_body"] = json.dumps(headers), body[:cap]
        is_upgrade = (hm.get_header(headers, "upgrade") or "").lower() == "websocket"
        timeout = self.settings.get("proxy.upstream_timeout")
        uwriter = None
        sent_head = False
        keep = client_keepalive
        try:
            ctx = self.certs.client_context(self.settings.get("proxy.verify_upstream")) if scheme == "https" else None
            ureader, uwriter = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if ctx else None, limit=2 ** 20),
                timeout)
            if ctx:
                so = uwriter.get_extra_info("ssl_object")
                entry["tls"] = json.dumps({"version": so.version(), "cipher": (so.cipher() or [None])[0]}) if so else None
            up = [(k, v) for k, v in headers if k.lower() not in hm.HOP_BY_HOP | {"content-length", "expect"}]
            if is_upgrade:
                up = [(k, v) for k, v in up if k.lower() != "sec-websocket-extensions"]  # agar payload tidak terkompresi
                up += [("Connection", "Upgrade"), ("Upgrade", "websocket")]
            else:
                up.append(("Connection", "close"))
            if not any(k.lower() == "host" for k, _ in up):
                up.insert(0, ("Host", host if port == default else f"{host}:{port}"))
            if body or method in ("POST", "PUT", "PATCH"):
                up.append(("Content-Length", str(len(body))))
            uwriter.write(hm.build_raw_request(method, path, up, body))
            await uwriter.drain()
            while True:  # lewati 1xx selain 101
                rhead = await asyncio.wait_for(read_head(ureader), timeout)
                first, rheaders = parse_head(rhead)
                _, code, *_ = first.split(" ", 2)
                status = int(code)
                if status != 100 and not (102 <= status < 200 and status != 101):
                    break
            entry["status"] = status
            entry["resp_headers"] = json.dumps(rheaders)
            entry["content_type"] = (hm.get_header(rheaders, "content-type") or "")[:200]
            ttfb = time.perf_counter()
            if status == 101:
                entry["duration_ms"] = round((ttfb - t0) * 1000, 2)
                cwriter.write(rhead)
                await cwriter.drain()
                hid = self._store(entry)
                await self._ws_tunnel(creader, cwriter, ureader, uwriter, hid, host, url)
                return False
            no_body = method == "HEAD" or status in (204, 304) or status < 200
            te = (hm.get_header(rheaders, "transfer-encoding") or "").lower()
            cl = hm.get_header(rheaders, "content-length")
            out = [(k, v) for k, v in rheaders if k.lower() not in hm.HOP_BY_HOP | {"content-length"}]
            if no_body:
                if cl is not None:
                    out.append(("Content-Length", cl))
                gen, mode = None, "none"
            elif "chunked" in te:
                gen, mode = iter_chunked(ureader), "chunked"
            elif cl is not None and cl.isdigit():
                gen, mode = iter_fixed(ureader, int(cl)), "fixed"
                out.append(("Content-Length", cl))
            else:
                gen, mode = iter_eof(ureader), "eof"
            if mode in ("chunked", "eof") and version.upper() == "HTTP/1.1":
                out.append(("Transfer-Encoding", "chunked"))
                chunk_out = True
            else:
                chunk_out = False
                if mode in ("chunked", "eof"):
                    keep = False
            out.append(("Connection", "keep-alive" if keep else "close"))
            reason_txt = first.split(" ", 2)[2] if len(first.split(" ", 2)) > 2 else hm.reason(status)
            head_out = f"HTTP/1.1 {status} {reason_txt}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in out) + "\r\n"
            cwriter.write(head_out.encode("latin-1", "replace"))
            sent_head = True
            stored, total = bytearray(), 0
            if gen is not None:
                it = gen.__aiter__()
                while True:
                    try:
                        chunk = await asyncio.wait_for(it.__anext__(), timeout)
                    except StopAsyncIteration:
                        break
                    total += len(chunk)
                    if len(stored) < cap:
                        stored += chunk[:cap - len(stored)]
                    if chunk_out:
                        cwriter.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    else:
                        cwriter.write(chunk)
                    await cwriter.drain()
                if chunk_out:
                    cwriter.write(b"0\r\n\r\n")
            await cwriter.drain()
            entry.update(resp_body=bytes(stored), resp_size=total, truncated=1 if total > len(stored) else 0,
                         duration_ms=round((time.perf_counter() - t0) * 1000, 2))
            if record:
                self._store(entry)
            return keep
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.stats["errors"] += 1
            msg = f"{type(exc).__name__}: {exc}"
            entry.update(error=msg, duration_ms=round((time.perf_counter() - t0) * 1000, 2))
            entry.setdefault("resp_headers", "[]")
            self.log("error", f"{method} {url} gagal: {msg}")
            if not sent_head:
                try:
                    await self._respond(cwriter, 502, f"EXVOLT X: gagal menghubungi upstream - {msg}".encode())
                except Exception:
                    pass
            if record:
                self._store(entry)
            return False
        finally:
            if uwriter is not None:
                try:
                    uwriter.close()
                except Exception:
                    pass

    def _store(self, entry):
        hid = self.db.add_history(entry, self.settings.get("history.max_entries"))
        row = dict(entry, id=hid)
        self.bus.publish("history", {k: row.get(k) for k in (
            "id", "ts", "scheme", "host", "port", "method", "url", "status", "content_type",
            "resp_size", "duration_ms", "in_scope", "error")} | {"source": "proxy"})
        for hook in self.hooks:
            asyncio.get_running_loop().run_in_executor(None, self._run_hook, hook, hid, row)
        return hid

    def _run_hook(self, hook, hid, row):
        try:
            hook(hid, row)
        except Exception as exc:
            self.log("error", f"Hook analisis gagal: {type(exc).__name__}: {exc}")

    # ---------------------------------------------------------- websocket
    async def _ws_tunnel(self, creader, cwriter, ureader, uwriter, hid, host, url):
        counts = {"n": 0}

        async def pump(r, w, direction):
            parser = WsParser()
            try:
                while True:
                    data = await r.read(65536)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
                    if parser is not None:
                        try:
                            for op, payload in parser.feed(data):
                                self._store_ws(hid, direction, op, payload, host, url)
                                counts["n"] += 1
                        except ProxyError as exc:
                            self.log("warn", f"Parser WebSocket dihentikan: {exc}")
                            parser = None
            except Exception:
                pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass

        await asyncio.gather(pump(creader, uwriter, "out"), pump(ureader, cwriter, "in"))
        self.db.x("UPDATE history SET note=? WHERE id=?", (f"{counts['n']} pesan WebSocket", hid))

    def _store_ws(self, hid, direction, op, payload, host, url):
        kind = WS_KINDS.get(op, f"op{op}")
        data = payload[:WS_PAYLOAD_CAP]
        mid, _ = self.db.x("INSERT INTO ws_messages(conn_id,ts,direction,opcode,kind,payload,length,host,url) "
                           "VALUES(?,?,?,?,?,?,?,?,?)", (hid, time.time(), direction, op, kind, data, len(payload), host, url))
        if mid % 500 == 0:
            self.db.x("DELETE FROM ws_messages WHERE id<=?", (mid - WS_MAX_ROWS,))
        self.bus.publish("ws_message", {"id": mid, "conn_id": hid, "direction": direction, "kind": kind,
                                        "length": len(payload), "host": host})
