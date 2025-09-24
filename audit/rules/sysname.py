"""Validation de la nomenclature des noms d'hôtes."""

from __future__ import annotations

import re
from typing import List

from .base_rules import BaseAuditRule


class SysnameRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "sysname"

    def run(self, info: dict) -> dict:
        hostname = str(info.get("hostname", "")).upper()

        prefixes = _split_csv(self.config.get("prefixes", ""))
        patterns = _split_csv(self.config.get("patterns", ""))

        allowed = any(hostname.startswith(prefix.upper()) for prefix in prefixes if prefix)
        if not allowed:
            allowed = any(re.fullmatch(pattern, hostname) for pattern in patterns if pattern)

        details = (
            f"Hostname '{info.get('hostname', 'N/A')}' conforme aux règles"
            if allowed
            else f"Hostname '{info.get('hostname', 'N/A')}' hors référentiel"
        )
        return {"name": self.name, "passed": allowed, "details": details}


def _split_csv(raw: str) -> List[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]
