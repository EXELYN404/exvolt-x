#!/usr/bin/env python3
"""EXVOLT X - Web Security Testing Platform (EXELYN404). Jalankan: python3 main.py"""
import argparse
import sys

if sys.version_info < (3, 10):
    sys.exit("EXVOLT X membutuhkan Python 3.10 atau lebih baru.")

try:
    import uvicorn
    import yaml  # noqa: F401
    import cryptography  # noqa: F401
    import starlette  # noqa: F401
except ImportError as exc:
    sys.exit(f"Dependensi belum terpasang ({exc.name}). Jalankan: pip install -r requirements.txt")

from exvolt import __version__
from exvolt.api.app import create_app
from exvolt.core.settings import Settings, is_loopback


def main():
    ap = argparse.ArgumentParser(description="EXVOLT X - platform pengujian keamanan web")
    ap.add_argument("--host", help="alamat bind UI (default dari config.yaml: 127.0.0.1)")
    ap.add_argument("--port", type=int, help="port UI (default 8080)")
    ap.add_argument("--config", help="path config.yaml")
    args = ap.parse_args()
    try:
        settings = Settings(args.config)
        patch = {}
        if args.host:
            patch["host"] = args.host
        if args.port:
            patch["port"] = args.port
        if patch:
            settings.update({"server": patch}, persist=False)
    except (RuntimeError, ValueError) as exc:
        sys.exit(f"Konfigurasi tidak valid: {exc}")
    host, port = settings.get("server.host"), settings.get("server.port")
    if not is_loopback(host) and not settings.get("server.auth_token"):
        sys.exit("Menolak bind non-localhost tanpa autentikasi. Setel server.auth_token (min. 16 karakter) di config.yaml.")
    print(f"EXVOLT X {__version__} oleh EXELYN404\nUI: http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}")
    uvicorn.run(create_app(settings), host=host, port=port, log_level="warning", ws_ping_interval=None)


if __name__ == "__main__":
    main()
