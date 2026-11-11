"""Intruder: pengujian request terkontrol (scope wajib, konfirmasi target, rate/concurrency limit, stop nyata)."""
from __future__ import annotations

import csv
import io
import itertools
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from ..core import http_client
from ..utils import httpmsg as hm

MARK = "§"
MODES = ("sniper", "battering_ram", "pitchfork", "cluster_bomb")


class IntruderError(ValueError):
    pass


class RateLimiter:
    def __init__(self, rps):
        self.interval, self.lock, self.next = 1.0 / rps, threading.Lock(), 0.0

    def wait(self, stop: threading.Event):
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next)
            self.next = t + self.interval
        while not stop.is_set():
            d = t - time.monotonic()
            if d <= 0:
                return
            stop.wait(min(d, 0.25))


def split_template(template: str):
    parts = template.split(MARK)
    if len(parts) % 2 == 0:
        raise IntruderError(f"tanda {MARK} tidak berpasangan")
    return parts[0::2], parts[1::2]  # literal, default_values


def generate(mode, n_pos, lists, cap):
    """Hasilkan tuple (indeks_posisi_terisi -> payload). Dibatasi `cap`."""
    if n_pos < 1:
        raise IntruderError(f"minimal satu posisi payload (tandai dengan {MARK}...{MARK})")
    if mode == "sniper":
        pl = lists[0] if lists else []
        gen = ((pos, p) for pos in range(n_pos) for p in pl)
        gen = ({pos: p} for pos, p in gen)
    elif mode == "battering_ram":
        gen = ({i: p for i in range(n_pos)} for p in (lists[0] if lists else []))
    elif mode == "pitchfork":
        if len(lists) < n_pos:
            raise IntruderError("pitchfork membutuhkan satu daftar payload per posisi")
        gen = ({i: v for i, v in enumerate(vals)} for vals in zip(*lists[:n_pos]))
    elif mode == "cluster_bomb":
        if len(lists) < n_pos:
            raise IntruderError("cluster_bomb membutuhkan satu daftar payload per posisi")
        gen = ({i: v for i, v in enumerate(vals)} for vals in itertools.product(*lists[:n_pos]))
    else:
        raise IntruderError(f"mode harus salah satu dari {MODES}")
    return list(itertools.islice(gen, cap + 1))


def estimate(mode, n_pos, lists):
    if mode == "sniper":
        return n_pos * len(lists[0]) if lists else 0
    if mode == "battering_ram":
        return len(lists[0]) if lists else 0
    if mode == "pitchfork":
        return min(len(l) for l in lists[:n_pos]) if len(lists) >= n_pos else 0
    total = 1
    for l in lists[:n_pos]:
        total *= len(l)
    return total if len(lists) >= n_pos else 0


class Attack:
    def __init__(self, aid, cfg, total):
        self.id, self.cfg, self.total = aid, cfg, total
        self.stop = threading.Event()
        self.results, self.done, self.errors = [], 0, 0
        self.state = "running"
        self.started, self.finished = time.time(), None
        self.lock = threading.Lock()
        self.handles = set()

    def summary(self):
        return {"id": self.id, "state": self.state, "total": self.total, "done": self.done, "errors": self.errors,
                "started": self.started, "finished": self.finished, "mode": self.cfg["mode"], "host": self.cfg["host_label"]}


class IntruderManager:
    def __init__(self, settings, guard, bus):
        self.settings, self.guard, self.bus = settings, guard, bus
        self.attacks: dict[int, Attack] = {}
        self._id = 0
        self.lock = threading.Lock()

    def _limits(self):
        return (self.settings.get("intruder.max_requests"), self.settings.get("intruder.max_concurrency"),
                self.settings.get("intruder.max_rps"))

    def start(self, req: dict):
        max_req, max_conc, max_rps = self._limits()
        template = req.get("template", "")
        scheme, host, port = req.get("scheme", "http"), req.get("host", "").strip(), req.get("port")
        if scheme not in ("http", "https") or not host:
            raise IntruderError("scheme/host tidak valid")
        mode = req.get("mode", "sniper")
        if mode not in MODES:
            raise IntruderError(f"mode harus salah satu dari {MODES}")
        conc = int(req.get("concurrency", 1))
        rps = float(req.get("rps", 5))
        if not 1 <= conc <= max_conc:
            raise IntruderError(f"concurrency harus 1-{max_conc}")
        if not 0 < rps <= max_rps:
            raise IntruderError(f"rps harus >0 dan <= {max_rps}")
        # konfirmasi target eksplisit: pengguna harus mengetik ulang host:port
        default = 443 if scheme == "https" else 80
        p = int(port) if port else default
        expected = f"{host}:{p}"
        if str(req.get("confirm_target", "")).strip().lower() != expected.lower():
            raise IntruderError(f"konfirmasi target salah: ketik persis '{expected}' untuk melanjutkan")
        literals, defaults = split_template(template)
        n_pos = len(defaults)
        lists = [[str(x) for x in l if str(x) != ""] for l in req.get("payloads", [])]
        n = estimate(mode, n_pos, lists)
        if n == 0:
            raise IntruderError("tidak ada kombinasi payload untuk dijalankan")
        if n > max_req:
            raise IntruderError(f"jumlah request ({n}) melebihi batas intruder.max_requests ({max_req})")
        plain = template.replace(MARK, "")
        method, url, headers, body = self._build_probe(plain, scheme, host, p)
        ok, why = self.guard.check(url)
        if not ok:
            raise IntruderError(f"target ditolak: {why}")
        combos = generate(mode, n_pos, lists, max_req)
        with self.lock:
            if any(a.state == "running" for a in self.attacks.values()):
                raise IntruderError("masih ada serangan yang berjalan; hentikan terlebih dahulu")
            self._id += 1
            att = Attack(self._id, {"mode": mode, "template": template, "scheme": scheme, "host": host, "port": p,
                                    "host_label": expected, "literals": literals, "defaults": defaults,
                                    "timeout": float(req.get("timeout", 15)), "conc": conc, "rps": rps,
                                    "follow": False}, len(combos))
            self.attacks[att.id] = att
            for old in sorted(self.attacks)[:-5]:
                if self.attacks[old].state != "running":
                    del self.attacks[old]
        threading.Thread(target=self._run, args=(att, combos), daemon=True, name=f"intruder-{att.id}").start()
        return att

    @staticmethod
    def _build_probe(raw, scheme, host, port):
        from .repeater import build_from_raw
        try:
            return build_from_raw(raw, scheme, host, port)
        except ValueError as exc:
            raise IntruderError(str(exc)) from exc

    def _render(self, att, combo):
        c, out = att.cfg, []
        for i, lit in enumerate(c["literals"]):
            out.append(lit)
            if i < len(c["defaults"]):
                out.append(combo.get(i, c["defaults"][i]))
        return "".join(out)

    def _run(self, att, combos):
        limiter = RateLimiter(att.cfg["rps"])
        c = att.cfg
        verify = self.settings.get("proxy.verify_upstream")
        max_bytes = min(self.settings.get("network.max_response_bytes"), 2 * 1024 * 1024)

        def one(idx_combo):
            idx, combo = idx_combo
            if att.stop.is_set():
                return
            limiter.wait(att.stop)
            if att.stop.is_set():
                return
            payload = " | ".join(combo[k] for k in sorted(combo))
            row = {"n": idx + 1, "payload": payload, "status": None, "length": None, "duration_ms": None, "error": None}
            handle = http_client.RequestHandle()
            att.handles.add(handle)
            try:
                raw = self._render(att, combo)
                method, url, headers, body = build_from_raw_safe(raw, c)
                ok, why = self.guard.check(url)  # periksa ulang: payload tidak boleh memperluas target
                if not ok:
                    raise http_client.HttpClientError(f"payload mengubah target ke luar scope: {why}")
                if urlsplit(url).netloc.lower() != _expected_netloc(c):
                    raise http_client.HttpClientError("payload mengubah host target; dibatalkan")
                r = http_client.send_request(method, url, headers, body, timeout=c["timeout"], verify=verify,
                                             max_bytes=max_bytes, handle=handle)
                row.update(status=r["status"], length=len(r["body"]), duration_ms=r["duration_ms"],
                           snippet=r["body"][:120].decode("utf-8", "replace"))
            except Exception as exc:
                row["error"] = str(exc)
                if att.stop.is_set():
                    row["error"] = "dibatalkan"
            finally:
                att.handles.discard(handle)
            with att.lock:
                att.results.append(row)
                att.done += 1
                if row["error"]:
                    att.errors += 1
                if att.done % 5 == 0 or att.done == att.total:
                    self.bus.publish("intruder", att.summary())

        try:
            with ThreadPoolExecutor(max_workers=c["conc"]) as ex:
                list(ex.map(one, list(enumerate(combos))))
        finally:
            att.state = "stopped" if att.stop.is_set() else "finished"
            att.finished = time.time()
            self.bus.publish("intruder", att.summary())

    def stop(self, aid):
        att = self.attacks.get(aid)
        if not att:
            return False
        att.stop.set()
        for h in list(att.handles):
            h.cancel()
        return True

    def get(self, aid):
        return self.attacks.get(aid)

    @staticmethod
    def export(att, fmt="csv"):
        rows = list(att.results)
        if fmt == "json":
            return json.dumps({"attack": att.summary(), "results": rows}, indent=2, ensure_ascii=False), "application/json"
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["n", "payload", "status", "length", "duration_ms", "error"])
        for r in rows:
            vals = [r["n"], r["payload"], r["status"], r["length"], r["duration_ms"], r["error"]]
            w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in vals])  # cegah CSV injection
        return buf.getvalue(), "text/csv"


def _expected_netloc(c):
    default = 443 if c["scheme"] == "https" else 80
    return c["host"].lower() if c["port"] == default else f"{c['host'].lower()}:{c['port']}"


def build_from_raw_safe(raw, c):
    from .repeater import build_from_raw
    return build_from_raw(raw, c["scheme"], c["host"], c["port"])
