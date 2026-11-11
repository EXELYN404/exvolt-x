"""Decoder: encode/decode nyata (tanpa keluaran buatan)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
from urllib.parse import quote, unquote

OPS = {
    "url": {"encode", "decode"},
    "base64": {"encode", "decode"},
    "base64url": {"encode", "decode"},
    "hex": {"encode", "decode"},
    "html": {"encode", "decode"},
    "unicode": {"encode", "decode"},
    "json": {"encode", "decode"},      # encode = minify, decode = pretty
    "jwt": {"decode"},
    "sha256": {"encode"},
    "sha512": {"encode"},
    "sha1": {"encode"},
    "md5": {"encode"},
}
MAX_INPUT = 8 * 1024 * 1024


class DecoderError(ValueError):
    pass


def _b64pad(s):
    s = re.sub(r"\s+", "", s)
    return s + "=" * (-len(s) % 4)


def _jwt(text):
    parts = text.strip().split(".")
    if len(parts) not in (2, 3):
        raise DecoderError("JWT harus terdiri dari 2-3 bagian dipisah titik")
    out = {}
    for name, seg in zip(("header", "payload"), parts[:2]):
        try:
            out[name] = json.loads(base64.urlsafe_b64decode(_b64pad(seg)).decode("utf-8"))
        except Exception as exc:
            raise DecoderError(f"bagian {name} bukan base64url/JSON valid: {exc}") from exc
    out["signature_present"] = len(parts) == 3 and bool(parts[2])
    out["signature_verified"] = False  # inspeksi saja, tanpa kunci
    notes = []
    alg = str(out["header"].get("alg", "")).lower()
    if alg == "none":
        notes.append("alg=none: token tidak bertanda tangan")
    if not out["signature_present"]:
        notes.append("tidak ada signature")
    out["catatan"] = notes
    return json.dumps(out, indent=2, ensure_ascii=False)


def transform(op: str, direction: str, text: str) -> str:
    if op not in OPS:
        raise DecoderError(f"operasi tidak dikenal: {op}")
    if direction not in OPS[op]:
        raise DecoderError(f"{op} tidak mendukung '{direction}'")
    if len(text) > MAX_INPUT:
        raise DecoderError("input terlalu besar (maks 8 MB)")
    enc = direction == "encode"
    try:
        if op == "url":
            return quote(text, safe="") if enc else unquote(text)
        if op == "base64":
            return base64.b64encode(text.encode()).decode() if enc else base64.b64decode(_b64pad(text), validate=False).decode("utf-8", "replace")
        if op == "base64url":
            return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=") if enc else base64.urlsafe_b64decode(_b64pad(text)).decode("utf-8", "replace")
        if op == "hex":
            return text.encode().hex() if enc else bytes.fromhex(re.sub(r"[\s:]|0x", "", text)).decode("utf-8", "replace")
        if op == "html":
            return html.escape(text) if enc else html.unescape(text)
        if op == "unicode":
            if enc:
                return "".join(c if ord(c) < 128 else (f"\\u{ord(c):04x}" if ord(c) < 0x10000 else f"\\U{ord(c):08x}") for c in text)
            return re.sub(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})",
                          lambda m: chr(int(m.group(1) or m.group(2), 16)), text)
        if op == "json":
            obj = json.loads(text)
            return json.dumps(obj, separators=(",", ":"), ensure_ascii=False) if enc else json.dumps(obj, indent=2, ensure_ascii=False)
        if op == "jwt":
            return _jwt(text)
        return hashlib.new(op, text.encode()).hexdigest()
    except DecoderError:
        raise
    except (ValueError, binascii.Error) as exc:
        raise DecoderError(f"gagal {direction} {op}: {exc}") from exc
