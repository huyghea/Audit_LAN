"""Contrôle de l'uptime des équipements."""

from __future__ import annotations

import re
from typing import Optional

from .base_rules import BaseAuditRule
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)

def parse_uptime(output: str) -> tuple[Optional[str], Optional[str], int]:
    reason_match = re.search(
        r"(Last\s+reboot\s+reason\s*:\s*(.+))|(Reboot\s+Cause\s*:\s*(.+))",
        output,
        re.IGNORECASE,
    )
    if reason_match:
        reason = (reason_match.group(2) or reason_match.group(4) or "NA").strip()
    else:
        reason = "NA"

    uptime_match = (
        re.search(r"\buptime\s+is\s+(.+)", output, re.IGNORECASE)
        or re.search(r"\bUptime\s+is\s+(.+)", output, re.IGNORECASE)
        or re.search(r"\bUp\s*Time\s*[:=]\s*(.+)", output, re.IGNORECASE)
    )

    if not uptime_match:
        return None, reason, 0

    uptime_str = uptime_match.group(1).strip()
    uptime_str = re.split(
        r"\s{2,}(Memory|CPU|Base|Software|ROM)",
        uptime_str,
    )[0].strip()

    weeks = days = hours = minutes = 0
    pattern = re.search(
        r"(?:(\d+)\s*weeks?)?\s*,?\s*"
        r"(?:(\d+)\s*days?)?\s*,?\s*"
        r"(?:(\d+)\s*hours?)?\s*,?\s*"
        r"(?:(\d+)\s*minutes?)?",
        uptime_str,
        re.IGNORECASE,
    )
    if pattern:
        weeks = int(pattern.group(1) or 0)
        days = int(pattern.group(2) or 0)
        hours = int(pattern.group(3) or 0)
        minutes = int(pattern.group(4) or 0)
    else:
        m_days = re.search(r"(\d+)\s*days?", uptime_str, re.IGNORECASE)
        if m_days:
            days = int(m_days.group(1))

    total_seconds = weeks * 7 * 86400 + days * 86400 + hours * 3600 + minutes * 60
    formatted = (
        f"{weeks} weeks, {days} days, {hours} hours, {minutes} minutes"
        if (weeks + days + hours + minutes) > 0
        else uptime_str
    )

    return formatted, reason, total_seconds


class UptimeRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "uptime"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {
                "name": self.name,
                "passed": False,
                "details": "Connexion SSH indisponible",
            }

        threshold = int(self.config.get("minimum_seconds", 86400))

        inventory_cache = info.get("hardware_inventory")
        cached_command = ""
        cached_source = "découverte initiale"
        if isinstance(inventory_cache, dict):
            cached_command = str(inventory_cache.get("command") or "").strip().lower()
            cached_source = str(inventory_cache.get("command") or cached_source)
            cached_output = str(inventory_cache.get("raw_output") or "")
            if cached_output:
                uptime_str, reason, total_seconds = parse_uptime(cached_output)
                if uptime_str is not None:
                    passed = total_seconds >= threshold
                    if passed:
                        details = (
                            f"Uptime {uptime_str} (raison reboot: {reason}) via {cached_source}"
                        )
                    else:
                        hours = threshold // 3600
                        details = (
                            f"Reboot récent ({uptime_str}) - seuil {hours}h via {cached_source}"
                        )
                    return {
                        "name": self.name,
                        "passed": passed,
                        "details": details,
                    }

        disable_commands = resolve_disable_paging_commands(
            info.get("device_type"),
            self.config.get("disable_paging", "screen-length disable"),
        )
        disable_paging(connection, disable_commands)

        commands = normalize_list(
            self.config.get(
                "commands",
                "display version,show version,show system information,show system",
            )
        )

        for command in commands:
            normalized = command.strip().lower()
            if normalized and normalized == cached_command:
                continue
            output = run_command_with_paging(connection, command)
            if not output:
                continue

            uptime_str, reason, total_seconds = parse_uptime(output)
            if uptime_str is None:
                continue

            passed = total_seconds >= threshold
            if passed:
                details = (
                    f"Uptime {uptime_str} (raison reboot: {reason}) via {command}"
                )
            else:
                hours = threshold // 3600
                details = (
                    f"Reboot récent ({uptime_str}) - seuil {hours}h via {command}"
                )

            return {
                "name": self.name,
                "passed": passed,
                "details": details,
            }

        return {
            "name": self.name,
            "passed": False,
            "details": "Aucune information d'uptime",
        }
