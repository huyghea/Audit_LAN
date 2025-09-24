"""Contrôle de l'état des ventilateurs."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .base_rules import BaseAuditRule
from ..utils import disable_paging, normalize_list, run_command_with_paging


def analyse_fans(output: str) -> Tuple[Optional[int], Optional[int]]:
    lines = output.strip().splitlines()
    relevant = [line for line in lines if re.search(r"(Normal|Abnormal|Faulty|Absent)", line, re.IGNORECASE)]
    total = len(relevant)
    ok = sum(1 for line in relevant if re.search(r"Normal", line, re.IGNORECASE))
    if total > 0:
        return ok, total

    failure_match = re.search(r"(\d+)\s*/\s*(\d+)\s*Fans in Failure State", output)
    if failure_match:
        ko = int(failure_match.group(1))
        total = int(failure_match.group(2))
        return total - ko, total

    ratio = re.search(r"(\d+)\s*/\s*(\d+)", output)
    if ratio:
        return int(ratio.group(1)), int(ratio.group(2))

    return None, None


class FanHealthRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "fan_health"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {"name": self.name, "passed": False, "details": "Connexion SSH indisponible"}

        disable_paging(
            connection,
            normalize_list(self.config.get("disable_paging", "screen-length disable,screen-length 0 temporary,no page")),
        )

        commands = normalize_list(self.config.get("commands", "display fan,display device,show system fans"))

        for command in commands:
            output = run_command_with_paging(connection, command)
            ok, total = analyse_fans(output)
            if ok is not None and total is not None:
                passed = total == 0 or ok == total
                if total == 0:
                    details = f"Aucun ventilateur détecté via {command}"
                    return {"name": self.name, "passed": True, "details": details}

                details = (
                    f"Ventilateurs {ok}/{total} OK via {command}"
                    if passed
                    else f"Anomalie ventilateurs {ok}/{total} via {command}"
                )

                if not passed:
                    details += " - vérifier les modules de refroidissement"

                return {"name": self.name, "passed": passed, "details": details}

        return {"name": self.name, "passed": False, "details": "Aucune donnée ventilateurs exploitable"}
