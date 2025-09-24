"""Contrôle du taux d'utilisation mémoire."""

from __future__ import annotations

import re
from typing import Optional

from .base_rules import BaseAuditRule
from ..utils import disable_paging, normalize_list, run_command_with_paging


def extract_usage_percent(output: str) -> Optional[float]:
    match = re.search(r"(\d+(?:\.\d+)?)\s*%", output)
    if match:
        try:
            return float(match.group(1))
        except ValueError:  # pragma: no cover - sécurité supplémentaire
            return None
    return None


class MemoryUsageRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "memory_usage"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {"name": self.name, "passed": False, "details": "Connexion SSH indisponible"}

        disable_paging(
            connection,
            normalize_list(self.config.get("disable_paging", "screen-length 0 temporary,screen-length disable,no page")),
        )

        commands = normalize_list(
            self.config.get("commands", "display memory,display memory-usage,display system resource")
        )

        percent: Optional[float] = None
        used_cmd = None
        for command in commands:
            output = run_command_with_paging(connection, command)
            percent = extract_usage_percent(output)
            if percent is not None:
                used_cmd = command
                break

        if percent is None:
            return {
                "name": self.name,
                "passed": False,
                "details": "Aucun pourcentage d'utilisation mémoire détecté",
            }

        threshold = float(self.config.get("threshold", 85.0))
        passed = percent <= threshold
        details = (
            f"Utilisation mémoire {percent:.1f}% (seuil {threshold:.1f}%)"
            + (f" via {used_cmd}" if used_cmd else "")
        )

        if not passed:
            details += " - capacité mémoire élevée"

        return {"name": self.name, "passed": passed, "details": details}
