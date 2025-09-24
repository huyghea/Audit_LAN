"""Contrôle de la configuration SNMP trap."""

from __future__ import annotations

import re
from typing import List

from .base_rules import BaseAuditRule
from ..utils import disable_paging, first_successful_command, normalize_list


class SnmpTrapCheckRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "snmp_trap_check"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {"name": self.name, "passed": False, "details": "Connexion SSH indisponible"}

        disable_commands = normalize_list(self.config.get("disable_paging", "screen-length 0 temporary,screen-length disable,no page"))
        disable_paging(connection, disable_commands)

        commands = normalize_list(self.config.get("commands", "display current-configuration | include snmp"))
        fallback = normalize_list(self.config.get("fallback_commands", "display snmp-agent trap-list"))

        used_cmd, output = first_successful_command(connection, commands)
        if not output and fallback:
            used_cmd, output = first_successful_command(connection, fallback)

        if not output:
            return {
                "name": self.name,
                "passed": False,
                "details": "Impossible de récupérer la configuration SNMP"
            }

        targets = normalize_list(self.config.get("required_targets", ""))
        issues = analyse_traps(output, targets)

        passed = not issues
        detail_msg = "; ".join(issues) if issues else f"Configuration SNMP conforme (commande: {used_cmd})"
        return {"name": self.name, "passed": passed, "details": detail_msg}


def analyse_traps(output: str, required_targets: List[str]) -> List[str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return ["Configuration SNMP incomplète ou sortie vide"]

    issues: List[str] = []
    trap_enabled = any(re.search(r"snmp-agent\s+trap\s+enable", line, re.IGNORECASE) for line in lines)
    if not trap_enabled:
        issues.append("Trap SNMP non activé")

    for target in required_targets:
        pattern = rf"snmp-agent\s+target-host.*{re.escape(target)}"
        if not any(re.search(pattern, line, re.IGNORECASE) for line in lines):
            issues.append(f"Trap vers {target} manquant")

    pagination_detected = any("---- More ----" in line for line in lines)
    if pagination_detected:
        issues.append("Pagination détectée : relancer la commande avec pagination désactivée")

    return issues
