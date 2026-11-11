"""Utilitas parsing dan format pesan HTTP."""
from __future__ import annotations

import http
import json
import re
import zlib
from urllib.parse import parse_qsl

try:  # opsional
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None

HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
}
MAX_DECODE = 32 * 1024 * 1024


def reason(code: int) -> str:
    try:
        return http.HTTPStatus(code).phrase
    except ValueError:
        return ""


def get_header(headers, name, default=None):
    n = name.lower()
    for k, v in headers:
        if k.lower() == n:
            return v
    return default


def get_all(headers, name):
    n = name.lower()
    return [v for k, v in headers if k.lower() == n]


def headers_to_text(headers, nl="\n"):
    return nl.join(f"{k}: {v}" for k, v in headers)


def text_to_headers(text):
    out = []
    for ln in text.replace("\r\n", "\n").split("\n"):
        if not ln.strip():
            continue
        if ":" not in ln:
            raise ValueError(f"Baris header tidak valid: {ln[:60]!r}")
        k, v = ln.split(":", 1)
        k = k.strip()
        if not k or re.search(r"\s", k):
            raise ValueError(f"Nama header tidak valid: {k[:60]!r}")
        out.append((k, v.strip()))
    return out


def split_raw(raw: bytes):
    i, j = raw.find(b"\r\n\r\n"), raw.find(b"\n\n")
    if i != -1 and (j == -1 or i < j):
        return raw[:i], raw[i + 4:]
    if j != -1:
        return raw[:j], raw[j + 2:]
    return raw, b""


def parse_raw_request(raw: bytes):
    head, body = split_raw(raw)
    lines = head.decode("latin-1").replace("\r\n", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("Request kosong")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("Request line tidak valid")
    method, target = parts[0].upper(), parts[1]
    if not re.fullmatch(r"[A-Z]{1,20}", method):
        raise ValueError("Method tidak valid")
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    return {"method": method, "target": target, "version": version,
            "headers": text_to_headers("\n".join(lines[1:])), "body": body}


def build_raw_request(method, target, headers, body=b"", version="HTTP/1.1") -> bytes:
    head = f"{method} {target} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return head.encode("latin-1", "replace") + (body or b"")


def _inflate(data, wbits):
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, MAX_DECODE)
    if d.unconsumed_tail:
        raise ValueError("hasil dekompresi terlalu besar")
    return out


def decode_body(headers, body: bytes):
    """Kembalikan (bytes terdekode, catatan)."""
    enc = (get_header(headers, "content-encoding") or "").lower().strip()
    if not body or enc in ("", "identity"):
        return body, None
    try:
        data = body
        for e in reversed([x.strip() for x in enc.split(",")]):
            if e in ("gzip", "x-gzip"):
                data = _inflate(data, 31)
            elif e == "deflate":
                try:
                    data = _inflate(data, 15)
                except zlib.error:
                    data = _inflate(data, -15)
            elif e == "br" and brotli:
                data = brotli.decompress(data)
            elif e == "identity":
                pass
            else:
                return body, f"encoding '{e}' tidak didukung (ditampilkan apa adanya)"
        return data, enc
    except Exception as exc:
        return body, f"gagal dekompresi: {exc}"


def hexdump(data: bytes, limit=8192) -> str:
    out = []
    chunk = data[:limit]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in row).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"{i:08x}  {hx}  |{asc}|")
    if len(data) > limit:
        out.append(f"... ({len(data) - limit} byte lagi)")
    return "\n".join(out)


def render_body(body: bytes, content_type: str = ""):
    if not body:
        return {"text": "", "binary": False}
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    cs = m.group(1) if m else "utf-8"
    sample = body[:4096]
    if b"\x00" not in sample or cs.lower().startswith("utf-16"):
        for enc in (cs, "utf-8"):
            try:
                return {"text": body.decode(enc), "binary": False}
            except (UnicodeDecodeError, LookupError):
                continue
        printable = sum(1 for b in sample if b >= 32 or b in (9, 10, 13)) / max(1, len(sample))
        if printable > 0.85:
            return {"text": body.decode("latin-1"), "binary": False}
    return {"text": hexdump(body), "binary": True}


def pretty(text: str, content_type: str = "") -> str:
    ct = (content_type or "").lower()
    s = text.lstrip()
    if "json" in ct or s.startswith(("{", "[")):
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            return text
    if "x-www-form-urlencoded" in ct:
        try:
            return "\n".join(f"{k} = {v}" for k, v in parse_qsl(text, keep_blank_values=True))
        except Exception:
            return text
    return text
