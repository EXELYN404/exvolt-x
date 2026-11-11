"""Penjaga target: scope + blocklist untuk semua modul aktif."""
from __future__ import annotations

import fnmatch

from .scope_manager import ScopeError, split_url


class TargetGuard:
    def __init__(self, settings, scope):
        self.settings, self.scope = settings, scope

    def check(self, url: str):
        """Return (ok, alasan). Dipakai Repeater, Intruder, TLS probe, dan redirect."""
        try:
            _, host, _ = split_url(url)
        except ScopeError as exc:
            return False, str(exc)
        for pat in self.settings.get("network.blocked_hosts", []):
            if fnmatch.fnmatch(host, pat.lower()):
                return False, f"host diblokir oleh pengaturan jaringan ({pat})"
        if self.settings.get("network.enforce_scope", True):
            ok, why = self.scope.check(url)
            if not ok:
                return False, f"di luar scope: {why}"
        return True, "ok"
