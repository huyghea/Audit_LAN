"""Contrôle des alimentations électriques."""

from __future__ import annotations

import re
from typing import Tuple

from .base_rules import BaseAuditRule
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)


def analyse_power(output: str) -> Tuple[int, int, int, int]:
    ok = len(
        re.findall(
            r"\b(Normal|OK|Present|Powered|Active)\b",
            output,
            re.IGNORECASE,
        )
    )
    fault = len(
        re.findall(
            r"\b(Fault|Abnormal|Fail|Defect|Error)\b",
            output,
            re.IGNORECASE,
        )
    )
    absent = len(
        re.findall(
            r"\b(Absent|Not Present|Missing)\b",
            output,
            re.IGNORECASE,
        )
    )

    resume = re.search(
        r"\((\d+)\s+fault\(s\),\s+(\d+)\s+absent\(s\),\s+(\d+)\s+OK\)",
        output,
    )
    if resume:
        fault, absent, ok = (int(resume.group(i)) for i in range(1, 4))

    bays = re.search(
        r"(\d+)\s*/\s*(\d+)\s*supply bays delivering power",
        output,
        re.IGNORECASE,
    )
    if bays:
        ok = int(bays.group(1))
        total = int(bays.group(2))
        absent = max(0, total - ok)
        return ok, fault, absent, total

    total = ok + fault + absent
    return ok, fault, absent, total


class PowerSupplyRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "power_supply"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {
                "name": self.name,
                "passed": False,
                "details": "Connexion SSH indisponible",
            }

        disable_commands = resolve_disable_paging_commands(
            info.get("device_type"),
            self.config.get(
                "disable_paging",
                "screen-length disable,screen-length 0 temporary,no page",
            ),
        )
        disable_paging(connection, disable_commands)

        commands = normalize_list(
            self.config.get(
                "commands",
                "display power,show system power-supply,show environment power",
            )
        )

        for command in commands:
            output = run_command_with_paging(connection, command)
            if not output:
                continue
            if "does not support" in output.lower():
                return {
                    "name": self.name,
                    "passed": True,
                    "details": (
                        "Équipement sans capteurs d'alimentation "
                        f"(commande {command})"
                    ),
                }

            ok, fault, absent, total = analyse_power(output)
            if total == 0:
                continue

            passed = fault == 0 and ok > 0
            if absent > 0 and passed:
                passed = False

            if passed:
                details = f"Alimentations OK {ok}/{total} via {command}"
            else:
                details = (
                    "Alimentations partielles "
                    f"{ok}/{total} (fault:{fault}, absent:{absent}) via {command}"
                )

            if not passed and ok == 0:
                details += " - aucune alimentation active"

            return {
                "name": self.name,
                "passed": passed,
                "details": details,
            }

        return {
            "name": self.name,
            "passed": False,
            "details": "Aucune donnée alimentation exploitable",
        }
