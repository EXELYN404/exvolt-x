"""Scanner pasif: setiap temuan wajib berbukti dari lalu lintas yang benar-benar tertangkap."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import parse_qsl, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..utils import httpmsg as hm

SEV = ("info", "low", "medium", "high", "critical")
SESSION_NAME = re.compile(r"(sess|sid|token|auth|jwt|login|csrf|xsrf)", re.I)
SENSITIVE_PARAM = re.compile(r"^(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?token|auth|session(id)?|sid)$", re.I)
ERROR_SIGNS = [
    (r"Traceback \(most recent call last\)", "Stack trace Python"),
    (r"Server Error in '/[^']*' Application", "Halaman error ASP.NET"),
    (r"(?:Fatal error|Warning|Parse error):.{0,120} on line \d+", "Pesan error PHP"),
    (r"at [\w.$]+\([\w]+\.java:\d+\)", "Stack trace Java"),
    (r"You have an error in your SQL syntax", "Pesan error SQL (MySQL)"),
    (r"SQLSTATE\[[0-9A-Z]+\]", "Pesan error SQL (PDO)"),
    (r"\bORA-\d{5}\b", "Pesan error Oracle"),
    (r"Microsoft OLE DB Provider|Unclosed quotation mark", "Pesan error SQL Server"),
]
PRIVATE_IP = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")


def _snippet(text, m, width=80):
    s = max(0, m.start() - width // 2)
    return text[s:m.end() + width // 2].replace("\n", " ")[:240]


class PassiveScanner:
    def __init__(self, db, bus, settings):
        self.db, self.bus, self.settings = db, bus, settings

    # ------------------------------------------------------------ simpan
    def _add(self, row, name, severity, confidence, description, evidence, remediation, key):
        host = row["host"]
        fkey = f"{name}|{host}|{key}"
        _, n = self.db.x(
            "INSERT OR IGNORE INTO findings(ts,name,severity,confidence,description,evidence,url,host,remediation,history_id,fkey) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), name, severity, confidence, description, evidence[:2000], row["url"], host, remediation,
             row["id"], fkey))
        if n:
            self.bus.publish("finding", {"name": name, "severity": severity, "host": host})
        return n

    # ------------------------------------------------------------ analisis
    def analyze_id(self, hid):
        row = self.db.get_history(hid)
        return self.analyze(row) if row else 0

    def analyze(self, row) -> int:
        if not row or not row.get("status"):
            return 0
        status = row["status"]
        rh = json.loads(row["resp_headers"] or "[]")
        qh = json.loads(row["req_headers"] or "[]")
        ct = (row.get("content_type") or "").lower()
        scheme, new = row["scheme"], 0
        body, _ = hm.decode_body(rh, row.get("resp_body") or b"")
        text = body[:1_000_000].decode("utf-8", "replace") if body and not (b"\x00" in body[:2048]) else ""
        is_html = "html" in ct
        ok2xx = 200 <= status < 300
        hdr = lambda n: hm.get_header(rh, n)
        add = lambda *a: self._add(row, *a)

        if status == 101:
            return 0
        if scheme == "http":
            new += add("Layanan diakses melalui HTTP tanpa TLS", "low", "certain",
                       "Respons dilayani lewat HTTP polos sehingga dapat disadap atau diubah di jaringan.",
                       f"{row['method']} {row['url']} -> {status}", "Layani seluruh konten lewat HTTPS dan alihkan HTTP ke HTTPS.", "http")
            if is_html and re.search(r"<input[^>]+type=[\"']?password", text, re.I):
                new += add("Form password dikirim melalui HTTP", "high", "certain",
                           "Halaman memuat input password tetapi dilayani tanpa TLS; kredensial dapat disadap.",
                           "Ditemukan <input type=password> pada respons HTTP", "Layani halaman login hanya lewat HTTPS.", "pwd")
        # --- header keamanan
        if ok2xx and is_html:
            csp = hdr("content-security-policy")
            if not csp:
                new += add("Header Content-Security-Policy tidak ada", "low", "certain",
                           "Tanpa CSP, dampak XSS tidak dibatasi oleh browser.",
                           f"Respons HTML {status} tanpa Content-Security-Policy", "Tambahkan CSP yang membatasi sumber skrip.", "csp")
            elif re.search(r"(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\*)", csp):
                new += add("Content-Security-Policy lemah", "low", "firm",
                           "CSP mengizinkan 'unsafe-inline'/'unsafe-eval' atau wildcard pada sumber skrip.",
                           f"Content-Security-Policy: {csp[:300]}", "Hapus 'unsafe-inline'/'unsafe-eval' dan gunakan nonce/hash.", "cspweak")
            if not hdr("x-frame-options") and not (csp and "frame-ancestors" in csp):
                new += add("Perlindungan clickjacking tidak ada", "low", "certain",
                           "Halaman dapat dibingkai oleh situs lain.",
                           "Tidak ada X-Frame-Options maupun CSP frame-ancestors", "Tambahkan X-Frame-Options: DENY atau CSP frame-ancestors.", "xfo")
            if not hdr("referrer-policy"):
                new += add("Header Referrer-Policy tidak ada", "info", "certain", "URL penuh dapat bocor lewat header Referer.",
                           "Referrer-Policy tidak ditemukan", "Setel Referrer-Policy: no-referrer atau strict-origin-when-cross-origin.", "rp")
            if not hdr("permissions-policy"):
                new += add("Header Permissions-Policy tidak ada", "info", "certain", "Fitur browser tidak dibatasi secara eksplisit.",
                           "Permissions-Policy tidak ditemukan", "Tambahkan Permissions-Policy yang membatasi fitur yang tidak dipakai.", "pp")
        if ok2xx and (hdr("x-content-type-options") or "").lower() != "nosniff":
            new += add("X-Content-Type-Options: nosniff tidak ada", "info", "certain", "Browser dapat menebak tipe MIME (MIME sniffing).",
                       f"X-Content-Type-Options={hdr('x-content-type-options')!r}", "Tambahkan X-Content-Type-Options: nosniff.", "xcto")
        if scheme == "https" and status < 400:
            hsts = hdr("strict-transport-security")
            if not hsts:
                new += add("Header HSTS tidak ada", "low", "certain", "Browser tidak dipaksa memakai HTTPS untuk host ini.",
                           "Strict-Transport-Security tidak ditemukan pada respons HTTPS", "Tambahkan Strict-Transport-Security: max-age=31536000; includeSubDomains.", "hsts")
            else:
                m = re.search(r"max-age=(\d+)", hsts, re.I)
                if not m or int(m.group(1)) < 15552000:
                    new += add("HSTS max-age terlalu pendek", "low", "certain", "Masa berlaku HSTS kurang dari 180 hari.",
                               f"Strict-Transport-Security: {hsts}", "Gunakan max-age minimal 15552000 (disarankan 31536000).", "hstsweak")
        # --- cookie
        for sc in hm.get_all(rh, "set-cookie"):
            parts = [p.strip() for p in sc.split(";")]
            if "=" not in parts[0]:
                continue
            cname = parts[0].split("=", 1)[0]
            attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts[1:]}
            sess = bool(SESSION_NAME.search(cname))
            ev = f"Set-Cookie: {cname}=<disembunyikan>; " + "; ".join(parts[1:])
            if scheme == "https" and "secure" not in attrs:
                new += add(f"Cookie '{cname}' tanpa atribut Secure", "medium" if sess else "low", "certain",
                           "Cookie dapat terkirim lewat HTTP polos.", ev, "Tambahkan atribut Secure.", f"secure:{cname}")
            if "httponly" not in attrs:
                new += add(f"Cookie '{cname}' tanpa atribut HttpOnly", "medium" if sess else "low", "certain",
                           "Cookie dapat dibaca JavaScript sehingga rentan dicuri lewat XSS.", ev, "Tambahkan atribut HttpOnly.", f"httponly:{cname}")
            ss = attrs.get("samesite", "").lower()
            if not ss:
                new += add(f"Cookie '{cname}' tanpa atribut SameSite", "info", "certain", "Perlindungan CSRF bergantung pada default browser.",
                           ev, "Tambahkan SameSite=Lax atau Strict.", f"samesite:{cname}")
            elif ss == "none" and "secure" not in attrs:
                new += add(f"Cookie '{cname}' SameSite=None tanpa Secure", "medium", "certain", "Browser modern menolak cookie ini; konfigurasi tidak konsisten.",
                           ev, "Tambahkan Secure atau ubah SameSite.", f"samesitenone:{cname}")
            if scheme == "http" and sess and "secure" not in attrs:
                new += add(f"Cookie sesi '{cname}' diset lewat HTTP", "medium", "firm", "Cookie bernama sesi dikirim melalui koneksi tidak terenkripsi.",
                           ev, "Gunakan HTTPS dan atribut Secure.", f"httpcookie:{cname}")
        # --- paparan informasi
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
            v = hdr(name)
            if v and (name != "server" or re.search(r"\d+\.\d+|/\d", v)):
                new += add(f"Header {name} membocorkan teknologi/versi", "low", "certain",
                           "Informasi versi memudahkan penyerang mencari kerentanan yang cocok.",
                           f"{name}: {v}", "Hilangkan atau samarkan header ini.", f"{name}:{v}")
        for pat, label in ERROR_SIGNS:
            m = re.search(pat, text)
            if m:
                new += add(f"Pesan error rinci terekspos: {label}", "medium", "firm",
                           "Respons memuat detail internal aplikasi yang tidak seharusnya terlihat pengguna.",
                           _snippet(text, m), "Nonaktifkan debug dan tampilkan pesan error generik.", f"{label}:{urlsplit(row['url']).path}")
        if is_html and re.search(r"<title>\s*Index of /|Directory listing for", text, re.I):
            new += add("Directory listing aktif", "medium", "firm", "Isi direktori dapat dilihat publik.",
                       "Halaman berjudul 'Index of /' atau 'Directory listing for'", "Nonaktifkan autoindex/directory listing.", urlsplit(row["url"]).path)
        m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", text, re.I)
        if m:
            new += add("Meta generator membocorkan platform", "info", "certain", "Tag meta generator menyebut platform dan versinya.",
                       m.group(0)[:200], "Hapus tag meta generator.", m.group(1))
        if text and not _is_private_host(row["host"]):
            m = PRIVATE_IP.search(text)
            if m:
                new += add("Alamat IP privat muncul pada respons", "low", "tentative", "Alamat jaringan internal dapat membocorkan topologi.",
                           _snippet(text, m), "Hapus alamat internal dari respons publik.", m.group(1))
        # --- CORS
        acao, acac = hdr("access-control-allow-origin"), (hdr("access-control-allow-credentials") or "").lower()
        origin = hm.get_header(qh, "origin")
        if acao == "*" and acac == "true":
            new += add("CORS: wildcard dengan credentials", "medium", "certain", "Kombinasi tidak valid yang menandakan salah konfigurasi.",
                       "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true", "Gunakan daftar origin eksplisit.", "corswild")
        elif origin and acao == origin and acac == "true" and origin != f"{scheme}://{row['host']}":
            new += add("CORS memantulkan Origin dengan credentials", "medium", "tentative", "Server mungkin mempercayai origin sembarang.",
                       f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}; Allow-Credentials: true", "Validasi Origin terhadap allowlist.", "corsreflect")
        # --- mixed content
        if scheme == "https" and is_html:
            m = re.search(r"<(?:script|link|iframe|img)[^>]+(?:src|href)=[\"']http://[^\"']+", text, re.I)
            if m:
                new += add("Mixed content: sumber HTTP di halaman HTTPS", "medium", "firm", "Sumber daya HTTP dapat disadap/dimodifikasi dan melemahkan halaman HTTPS.",
                           m.group(0)[:240], "Muat semua sumber daya lewat HTTPS.", urlsplit(row["url"]).path)
        # --- data sensitif di URL
        for k, _v in parse_qsl(urlsplit(row["url"]).query, keep_blank_values=True):
            if SENSITIVE_PARAM.match(k):
                new += add(f"Parameter sensitif '{k}' pada URL", "low", "tentative", "Nilai pada URL tersimpan di log, riwayat browser, dan header Referer.",
                           f"Parameter query: {k}=<disembunyikan>", "Kirim data sensitif lewat body POST atau header.", f"param:{k}")
        # --- cache
        cc = (hdr("cache-control") or "").lower()
        if hm.get_all(rh, "set-cookie") and is_html and "no-store" not in cc and "private" not in cc:
            new += add("Respons ber-cookie tanpa Cache-Control no-store/private", "low", "tentative", "Respons personal dapat di-cache oleh proxy bersama.",
                       f"Cache-Control: {hdr('cache-control')!r}", "Tambahkan Cache-Control: no-store atau private.", "cache")
        # --- TLS upstream teramati
        if row.get("tls"):
            try:
                t = json.loads(row["tls"])
            except ValueError:
                t = {}
            if t.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                new += add("Server menegosiasikan versi TLS usang", "medium", "certain", "Protokol TLS lama memiliki kelemahan yang diketahui.",
                           f"Versi dinegosiasikan: {t['version']}, cipher: {t.get('cipher')}", "Nonaktifkan TLS < 1.2.", "tlsold")
        return new

    # ------------------------------------------------------------ TLS probe
    def tls_probe(self, host, port=443, timeout=10):
        """Handshake TLS nyata untuk memeriksa sertifikat dan protokol. Pemanggil wajib memeriksa scope."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der, version, cipher = s.getpeercert(True), s.version(), s.cipher()
        cert = x509.load_der_x509_certificate(der)
        now = dt.datetime.now(dt.timezone.utc)
        pk = cert.public_key()
        key_desc = (f"RSA {pk.key_size}" if isinstance(pk, rsa.RSAPublicKey)
                    else f"EC {pk.curve.name}" if isinstance(pk, ec.EllipticCurvePublicKey) else type(pk).__name__)
        res = {"host": host, "port": port, "version": version, "cipher": cipher[0] if cipher else None,
               "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
               "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
               "key": key_desc, "sig_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
               "self_signed": cert.subject == cert.issuer, "legacy_protocols": {}}
        for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c2.check_hostname, c2.verify_mode = False, ssl.CERT_NONE
                c2.minimum_version = c2.maximum_version = ver
                with socket.create_connection((host, port), timeout=timeout) as r2, c2.wrap_socket(r2, server_hostname=host):
                    res["legacy_protocols"][label] = "diterima"
            except Exception:
                res["legacy_protocols"][label] = "ditolak atau tidak dapat diuji oleh klien lokal"
        row = {"id": None, "host": host, "url": f"https://{host}:{port}/"}
        found = []

        def add(name, sev, conf, desc, ev, rem, key):
            found.append((name, sev, conf, desc, ev, rem, key))
        if cert.not_valid_after_utc < now:
            add("Sertifikat TLS kedaluwarsa", "high", "certain", "Sertifikat sudah lewat masa berlaku.", f"notAfter={res['not_after']}", "Perbarui sertifikat.", "expired")
        elif (cert.not_valid_after_utc - now).days < 30:
            add("Sertifikat TLS segera kedaluwarsa", "low", "certain", "Sertifikat berakhir dalam kurang dari 30 hari.", f"notAfter={res['not_after']}", "Perbarui sertifikat.", "expiring")
        if res["self_signed"]:
            add("Sertifikat TLS self-signed", "low", "certain", "Subjek sama dengan issuer; klien tidak dapat memvalidasi rantai.", f"subject=issuer={res['subject']}", "Gunakan sertifikat dari CA tepercaya.", "selfsigned")
        if isinstance(pk, rsa.RSAPublicKey) and pk.key_size < 2048:
            add("Kunci RSA lemah", "medium", "certain", "Kunci RSA < 2048 bit.", f"Kunci: {key_desc}", "Gunakan RSA >= 2048 atau ECDSA.", "weakkey")
        if res["sig_hash"] in ("sha1", "md5"):
            add("Algoritma tanda tangan sertifikat lemah", "medium", "certain", "Sertifikat memakai hash lemah.", f"signature hash: {res['sig_hash']}", "Terbitkan ulang dengan SHA-256.", "weaksig")
        if version in ("TLSv1", "TLSv1.1"):
            add("Server menegosiasikan versi TLS usang", "medium", "certain", "Protokol TLS lama.", f"Versi: {version}", "Nonaktifkan TLS < 1.2.", "tlsold")
        for label, st in res["legacy_protocols"].items():
            if st == "diterima":
                add(f"Server menerima {label}", "medium", "certain", "Server menerima protokol usang pada percobaan handshake nyata.", f"Handshake {label} berhasil", "Nonaktifkan TLS < 1.2.", label)
        n = 0
        for f in found:
            n += self._add(row, *f)
        res["new_findings"] = n
        res["findings"] = [{"name": f[0], "severity": f[1], "evidence": f[4]} for f in found]
        return res


def _is_private_host(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".local")
