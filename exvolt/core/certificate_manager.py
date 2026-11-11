"""CA lokal + sertifikat leaf per-host untuk intersepsi HTTPS."""
from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import os
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "EXVOLT X Local CA (EXELYN404)"


def _now():
    return dt.datetime.now(dt.timezone.utc)


class CertificateManager:
    def __init__(self, cert_dir):
        self.dir = cert_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.lock = threading.RLock()
        self.ca_key = self.ca_cert = None
        self._ctx = collections.OrderedDict()
        self._client = {}
        self.load_or_create()

    # -------------------------------------------------------------- CA
    @property
    def ca_pem_path(self):
        return self.dir / "ca.pem"

    @property
    def ca_key_path(self):
        return self.dir / "ca.key"

    def load_or_create(self):
        if self.ca_pem_path.exists() and self.ca_key_path.exists():
            self.ca_cert = x509.load_pem_x509_certificate(self.ca_pem_path.read_bytes())
            self.ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), None)
            return
        self.regenerate()

    def regenerate(self):
        with self.lock:
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EXELYN404")])
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(_now() - dt.timedelta(days=1))
                    .not_valid_after(_now() + dt.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                    .sign(key, hashes.SHA256()))
            fd = os.open(self.ca_key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            self.ca_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            self.ca_key, self.ca_cert = key, cert
            self._ctx.clear()

    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def ca_der(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.DER)

    def info(self):
        c = self.ca_cert
        return {"subject": c.subject.rfc4514_string(), "not_after": c.not_valid_after_utc.isoformat(),
                "sha256": c.fingerprint(hashes.SHA256()).hex(), "path": str(self.ca_pem_path)}

    # ------------------------------------------------------------ leaf
    def _leaf(self, host: str):
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self.ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_now() - dt.timedelta(days=1)).not_valid_after(_now() + dt.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([san]), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), False)
                .sign(self.ca_key, hashes.SHA256()))
        return cert, key

    def server_context(self, host: str) -> ssl.SSLContext:
        host = host.lower().strip("[]")
        with self.lock:
            if host in self._ctx:
                self._ctx.move_to_end(host)
                return self._ctx[host]
            cert, key = self._leaf(host)
            pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            tmpdir = self.dir / "tmp"
            tmpdir.mkdir(exist_ok=True)
            fd, path = tempfile.mkstemp(dir=tmpdir, suffix=".pem")  # mode 0600
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(pem)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(path)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            ctx.set_alpn_protocols(["http/1.1"])  # paksa HTTP/1.1 agar dapat diparse
            self._ctx[host] = ctx
            if len(self._ctx) > 256:
                self._ctx.popitem(last=False)
            return ctx

    def client_context(self, verify: bool) -> ssl.SSLContext:
        with self.lock:
            if verify not in self._client:
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["http/1.1"])
                self._client[verify] = ctx
            return self._client[verify]
