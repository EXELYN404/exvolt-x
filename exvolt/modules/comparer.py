"""Comparer: diff teks dan JSON nyata."""
from __future__ import annotations

import difflib
import html
import json


def _norm(text, ws, case):
    if ws:
        text = "\n".join(" ".join(ln.split()) for ln in text.splitlines())
    return text.lower() if case else text


def text_diff(a: str, b: str, ignore_ws=False, ignore_case=False):
    la, lb = _norm(a, ignore_ws, ignore_case).splitlines(), _norm(b, ignore_ws, ignore_case).splitlines()
    ra, rb = a.splitlines(), b.splitlines()
    sm = difflib.SequenceMatcher(None, la, lb, autojunk=False)
    rows, changes = [], 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({"op": "equal", "l": ra[i1 + k], "r": rb[j1 + k], "ln": i1 + k + 1, "rn": j1 + k + 1})
            continue
        changes += max(i2 - i1, j2 - j1)
        n = max(i2 - i1, j2 - j1)
        for k in range(n):
            left = ra[i1 + k] if i1 + k < i2 else None
            right = rb[j1 + k] if j1 + k < j2 else None
            op = "change" if left is not None and right is not None else ("delete" if left is not None else "insert")
            rows.append({"op": op, "l": left, "r": right,
                         "ln": i1 + k + 1 if left is not None else None, "rn": j1 + k + 1 if right is not None else None})
    return {"mode": "text", "rows": rows, "changes": changes, "identical": changes == 0,
            "left_lines": len(ra), "right_lines": len(rb)}


def _walk(a, b, path, out, ignore_case):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else str(k)
            if k not in a:
                out.append({"op": "insert", "path": p, "l": None, "r": b[k]})
            elif k not in b:
                out.append({"op": "delete", "path": p, "l": a[k], "r": None})
            else:
                _walk(a[k], b[k], p, out, ignore_case)
    elif isinstance(a, list) and isinstance(b, list):
        for i in range(max(len(a), len(b))):
            p = f"{path}[{i}]"
            if i >= len(a):
                out.append({"op": "insert", "path": p, "l": None, "r": b[i]})
            elif i >= len(b):
                out.append({"op": "delete", "path": p, "l": a[i], "r": None})
            else:
                _walk(a[i], b[i], p, out, ignore_case)
    else:
        same = (a.lower() == b.lower()) if ignore_case and isinstance(a, str) and isinstance(b, str) else a == b
        if not same or type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
            if not same:
                out.append({"op": "change", "path": path or "$", "l": a, "r": b})


def json_diff(a: str, b: str, ignore_case=False):
    try:
        ja, jb = json.loads(a), json.loads(b)
    except ValueError as exc:
        raise ValueError(f"input bukan JSON valid: {exc}") from exc
    out = []
    _walk(ja, jb, "", out, ignore_case)
    return {"mode": "json", "diffs": out, "changes": len(out), "identical": not out}


def compare(a: str, b: str, mode="text", ignore_ws=False, ignore_case=False):
    if len(a) > 8_000_000 or len(b) > 8_000_000:
        raise ValueError("input terlalu besar (maks 8 MB per sisi)")
    if mode == "json":
        return json_diff(a, b, ignore_case)
    if mode == "text":
        return text_diff(a, b, ignore_ws, ignore_case)
    raise ValueError("mode harus 'text' atau 'json'")


def export_html(result: dict, title="Hasil Perbandingan EXVOLT X") -> str:
    e = html.escape
    rows = []
    if result["mode"] == "text":
        for r in result["rows"]:
            rows.append(f"<tr class='{r['op']}'><td>{r['ln'] or ''}</td><td><pre>{e(r['l'] or '')}</pre></td>"
                        f"<td>{r['rn'] or ''}</td><td><pre>{e(r['r'] or '')}</pre></td></tr>")
        body = "<table>" + "".join(rows) + "</table>"
    else:
        for d in result["diffs"]:
            rows.append(f"<tr class='{d['op']}'><td>{e(d['path'])}</td><td><pre>{e(json.dumps(d['l'], ensure_ascii=False))}</pre></td>"
                        f"<td><pre>{e(json.dumps(d['r'], ensure_ascii=False))}</pre></td></tr>")
        body = "<table><tr><th>Path</th><th>Kiri</th><th>Kanan</th></tr>" + "".join(rows) + "</table>"
    css = ("body{font:13px system-ui;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;"
           "padding:2px 6px;vertical-align:top}pre{margin:0;white-space:pre-wrap;font:12px monospace}"
           ".change{background:#fff3cd}.insert{background:#d4edda}.delete{background:#f8d7da}")
    return (f"<!doctype html><meta charset=utf-8><title>{e(title)}</title><style>{css}</style>"
            f"<h2>{e(title)}</h2><p>Perubahan: {result['changes']}</p>{body}")
