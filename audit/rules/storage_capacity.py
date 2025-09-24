"""Contrôle de l'espace de stockage et des firmwares présents."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .base_rules import BaseAuditRule
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)

def extract_disk_usage(output: str) -> Tuple[Optional[int], Optional[int]]:
    for line in output.splitlines():
        match = re.search(
            r"([\d,]+)\s*KB\s+total(?:\s+available)?\s*\(\s*([\d,]+)\s*KB\s+free",
            line,
            flags=re.IGNORECASE,
        )
        if match:
            try:
                total = int(match.group(1).replace(",", ""))
                free = int(match.group(2).replace(",", ""))
                return total, free
            except ValueError:
                continue
    return None, None


def extract_firmwares(output: str) -> List[Tuple[str, int]]:
    firmwares: List[Tuple[str, int]] = []
    for line in output.splitlines():
        lower = line.lower()
        if not any(ext in lower for ext in (".bin", ".cc", ".img", ".ipe")):
            continue

        file_match = re.search(r"(\S+\.(?:bin|cc|img|ipe))", line, re.IGNORECASE)
        if not file_match:
            continue

        size_match = re.search(r"-rw-\s+([\d,]+)", line)
        size_value: Optional[int] = None
        if size_match:
            try:
                size_value = int(size_match.group(1).replace(",", ""))
            except ValueError:
                size_value = None

        if size_value is None:
            candidates = []
            for candidate in re.findall(r"([\d,]+)", line):
                try:
                    candidates.append(int(candidate.replace(",", "")))
                except ValueError:
                    continue
            if candidates:
                size_value = max(candidates)

        if size_value is not None:
            firmwares.append((file_match.group(1), size_value))

    return firmwares


class StorageCapacityRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "storage_capacity"

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
                "screen-length disable,screen-length 0 temporary,no page,"
                "terminal length 0",
            ),
        )
        disable_paging(connection, disable_commands)

        commands = normalize_list(
            self.config.get("commands", "dir,show flash,display flash")
        )

        for command in commands:
            output = run_command_with_paging(connection, command)
            if not output.strip():
                continue
            if any(
                keyword in output
                for keyword in ("Unrecognized", "Invalid", "Unknown command")
            ):
                continue

            total_kb, free_kb = extract_disk_usage(output)
            firmwares = extract_firmwares(output)

            if free_kb is not None and firmwares:
                firmware_name, firmware_size = max(firmwares, key=lambda item: item[1])
                firmware_kb = firmware_size / 1024
                passed = free_kb > firmware_kb
                details = (
                    "Libre: "
                    f"{free_kb} KB | Firmware max: {firmware_name} "
                    f"({firmware_kb:.0f} KB) via {command}"
                )
                if not passed:
                    details += " - espace insuffisant"
                return {
                    "name": self.name,
                    "passed": passed,
                    "details": details,
                }

            if free_kb is None and firmwares:
                firmware_name, firmware_size = max(firmwares, key=lambda item: item[1])
                details = (
                    f"Firmware {firmware_name} ({firmware_size} B) détecté via {command}"
                    " - incapacité à vérifier l'espace libre"
                )
                return {
                    "name": self.name,
                    "passed": False,
                    "details": details,
                }

            if free_kb is not None and not firmwares:
                return {
                    "name": self.name,
                    "passed": True,
                    "details": (
                        f"Libre: {free_kb} KB - aucun firmware détecté via {command}"
                    ),
                }

        return {
            "name": self.name,
            "passed": False,
            "details": "Aucune information de stockage exploitable",
        }
