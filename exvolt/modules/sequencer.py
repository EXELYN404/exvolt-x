"""Sequencer: ekstraksi token dari lalu lintas nyata dan analisis statistik atas data terkumpul."""
from __future__ import annotations

import collections
import json
import math
import re
import time

from ..utils import httpmsg as hm


class SequencerError(ValueError):
    pass


def extract_from_row(row, kind, name):
    """kind: cookie | header | body_regex. Mengembalikan daftar token."""
    rh = json.loads(row["resp_headers"] or "[]")
    out = []
    if kind == "cookie":
        for sc in hm.get_all(rh, "set-cookie"):
            first = sc.split(";", 1)[0]
            if "=" in first and first.split("=", 1)[0].strip() == name:
                out.append(first.split("=", 1)[1].strip())
    elif kind == "header":
        out += hm.get_all(rh, name)
    elif kind == "body_regex":
        try:
            rx = re.compile(name)
        except re.error as exc:
            raise SequencerError(f"regex tidak valid: {exc}") from exc
        body, _ = hm.decode_body(rh, row.get("resp_body") or b"")
        for m in rx.finditer(body[:1_000_000].decode("utf-8", "replace")):
            out.append(m.group(1) if m.groups() else m.group(0))
    else:
        raise SequencerError("kind harus cookie, header, atau body_regex")
    return [t for t in out if t][:50]


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _erfc(x):
    return math.erfc(x)


def analyze(tokens: list[str]):
    n = len(tokens)
    if n < 2:
        raise SequencerError("dibutuhkan minimal 2 token untuk analisis")
    res = {"count": n}
    lens = [len(t) for t in tokens]
    res["unique"] = len(set(tokens))
    res["duplicates"] = n - res["unique"]
    res["length"] = {"min": min(lens), "max": max(lens), "mean": round(sum(lens) / n, 2)}
    allchars = "".join(tokens)
    charset = sorted(set(allchars))
    res["charset_size"] = len(charset)
    res["charset"] = "".join(charset)[:128]
    res["entropy_per_char_bits"] = round(shannon(allchars), 4)
    res["entropy_max_per_char_bits"] = round(math.log2(len(charset)), 4) if len(charset) > 1 else 0.0
    res["entropy_total_est_bits"] = round(res["entropy_per_char_bits"] * res["length"]["mean"], 2)
    # entropi per posisi (hanya jika panjang sama dan sampel cukup)
    if res["length"]["min"] == res["length"]["max"] and n >= 20:
        pos = [round(shannon("".join(t[i] for t in tokens)), 3) for i in range(res["length"]["min"])]
        res["position_entropy"] = pos
        res["position_entropy_mean"] = round(sum(pos) / len(pos), 3)
    # uji bit: setiap token yang dapat dibaca sebagai hex atau base64 diubah menjadi bit
    bits = _to_bits(tokens)
    if bits and len(bits) >= 128:
        ones = sum(bits)
        nb = len(bits)
        z = abs(ones - nb / 2) / math.sqrt(nb / 4)
        res["bit_test"] = {"bits": nb, "ones_ratio": round(ones / nb, 4), "monobit_p": round(_erfc(z / math.sqrt(2)), 4)}
        runs = 1 + sum(1 for i in range(1, nb) if bits[i] != bits[i - 1])
        pi = ones / nb
        if abs(pi - 0.5) < 2 / math.sqrt(nb):
            p = _erfc(abs(runs - 2 * nb * pi * (1 - pi)) / (2 * math.sqrt(2 * nb) * pi * (1 - pi)))
            res["bit_test"]["runs_p"] = round(p, 4)
    # pola berurutan: apakah token numerik / bertambah?
    nums = [_as_int(t) for t in tokens]
    if all(v is not None for v in nums):
        diffs = [b - a for a, b in zip(nums, nums[1:])]
        if diffs:
            same = collections.Counter(diffs).most_common(1)[0]
            res["numeric"] = {"monotonic_increasing": all(d > 0 for d in diffs), "common_delta": same[0],
                              "common_delta_share": round(same[1] / len(diffs), 3)}
    # prefix/suffix konstan
    pref = _common_prefix(tokens)
    res["common_prefix"] = pref[:40]
    verdict = []
    if res["duplicates"]:
        verdict.append(f"{res['duplicates']} token duplikat dari {n} sampel: indikasi ruang token kecil atau pengulangan.")
    if res.get("numeric", {}).get("common_delta_share", 0) > 0.5:
        verdict.append("Token numerik dengan selisih dominan: dapat diprediksi.")
    if pref and len(pref) >= max(4, int(res["length"]["mean"] * 0.5)):
        verdict.append("Awalan bersama sangat panjang: sebagian besar token konstan.")
    if res["entropy_total_est_bits"] < 64:
        verdict.append(f"Estimasi entropi total {res['entropy_total_est_bits']} bit di bawah 64 bit.")
    bt = res.get("bit_test")
    if bt and bt["monobit_p"] < 0.01:
        verdict.append("Uji monobit gagal (p<0.01): distribusi bit tidak acak.")
    if n < 100:
        verdict.append(f"Sampel hanya {n}; analisis statistik kurang kuat (disarankan >= 100).")
    res["observations"] = verdict or ["Tidak ada indikasi kelemahan pada uji yang dijalankan (bukan jaminan keamanan)."]
    return res


def _to_bits(tokens):
    bits = []
    for t in tokens:
        data = None
        if re.fullmatch(r"[0-9a-fA-F]{16,}", t) and len(t) % 2 == 0:
            data = bytes.fromhex(t)
        elif re.fullmatch(r"[A-Za-z0-9_-]{16,}={0,2}", t):
            import base64
            try:
                data = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
            except Exception:
                data = None
        if data is None:
            return []
        for b in data:
            bits.extend((b >> i) & 1 for i in range(7, -1, -1))
    return bits


def _as_int(t):
    try:
        return int(t, 10) if re.fullmatch(r"\d{1,30}", t) else None
    except ValueError:
        return None


def _common_prefix(tokens):
    first, last = min(tokens), max(tokens)
    i = 0
    while i < min(len(first), len(last)) and first[i] == last[i]:
        i += 1
    return first[:i]


class Sequencer:
    def __init__(self, db, bus):
        self.db, self.bus = db, bus
        self.live = {}  # nama -> (kind, name) untuk penangkapan otomatis dari lalu lintas

    def create(self, name, source):
        if not re.fullmatch(r"[\w .-]{1,60}", name):
            raise SequencerError("nama set 1-60 karakter (huruf, angka, spasi, . _ -)")
        self.db.x("INSERT OR IGNORE INTO token_sets(name,source,created) VALUES(?,?,?)", (name, source, time.time()))

    def sets(self):
        return self.db.q("SELECT s.name, s.source, s.created, (SELECT COUNT(*) FROM tokens t WHERE t.set_name=s.name) AS count "
                         "FROM token_sets s ORDER BY s.created DESC")

    def add_tokens(self, name, tokens, hid=None):
        with self.db.tx() as c:
            c.executemany("INSERT INTO tokens(set_name,value,ts,history_id) VALUES(?,?,?,?)",
                          [(name, t, time.time(), hid) for t in tokens])
        c = self.db.one("SELECT COUNT(*) c FROM tokens WHERE set_name=?", (name,))["c"]
        if c > 100000:
            self.db.x("DELETE FROM tokens WHERE id IN (SELECT id FROM tokens WHERE set_name=? ORDER BY id LIMIT ?)", (name, c - 100000))

    def tokens(self, name, limit=100000):
        return [r["value"] for r in self.db.q("SELECT value FROM tokens WHERE set_name=? ORDER BY id LIMIT ?", (name, limit))]

    def delete(self, name):
        self.db.x("DELETE FROM tokens WHERE set_name=?", (name,))
        self.db.x("DELETE FROM token_sets WHERE name=?", (name,))
        self.live.pop(name, None)

    def start_live(self, name, kind, extract):
        if kind not in ("cookie", "header", "body_regex"):
            raise SequencerError("kind harus cookie, header, atau body_regex")
        if kind == "body_regex":
            try:
                re.compile(extract)
            except re.error as exc:
                raise SequencerError(f"regex tidak valid: {exc}") from exc
        self.create(name, f"{kind}:{extract}")
        self.live[name] = (kind, extract)

    def stop_live(self, name):
        return self.live.pop(name, None) is not None

    def hook(self, hid, row):
        """Dipanggil untuk setiap transaksi tertangkap: kumpulkan token dari lalu lintas nyata."""
        if not self.live or row.get("source") != "proxy":
            return
        for name, (kind, ex) in list(self.live.items()):
            toks = extract_from_row(row, kind, ex)
            if toks:
                self.add_tokens(name, toks, hid)
                self.bus.publish("sequencer", {"set": name, "added": len(toks)})
