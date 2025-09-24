"""Inventaire matériel basé sur les sorties CLI."""

from __future__ import annotations

import re
from typing import Dict, Optional

from .base_rules import BaseAuditRule
from ..parsers import clean_cli_output, extract_model, extract_version_and_firmware
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)

INVALID_PATTERN = re.compile(r"(Invalid|Unrecognized|Incomplete input)", re.IGNORECASE)


class HardwareInventoryRule(BaseAuditRule):
    """Collecte le modèle, la version et le firmware."""

    @property
    def name(self) -> str:
        return "hardware_inventory"

    def _format_result(
        self,
        model: str,
        version: str,
        firmware: str,
        source: Optional[str],
    ) -> Dict[str, object]:
        suffix = f" via {source}" if source else ""
        details = f"Modèle: {model} | Version: {version} | Firmware: {firmware}{suffix}"
        passed = model != "N/A" and version != "N/A"
        if not passed:
            details += " - informations partielles"
        return {
            "name": self.name,
            "passed": passed,
            "details": details,
        }

    def _result_from_cache(self, cache: dict) -> Optional[Dict[str, object]]:
        raw_output = cache.get("raw_output", "")
        model = cache.get("model") or "N/A"
        version = cache.get("version") or "N/A"
        firmware = cache.get("firmware") or "N/A"

        if raw_output:
            model_raw = extract_model(raw_output)
            version_raw, firmware_raw = extract_version_and_firmware(raw_output)
            if model_raw != "N/A":
                model = model_raw
            if version_raw != "N/A":
                version = version_raw
            if firmware_raw != "N/A":
                firmware = firmware_raw

        if model != "N/A" and version != "N/A":
            source = cache.get("command") or "découverte initiale"
            return self._format_result(model, version, firmware, source)
        return None

    def _lookup_model_with_extras(self, connection) -> str:
        extra_commands = normalize_list(
            self.config.get(
                "extra_commands",
                "display device manuinfo,display device,show inventory",
            )
        )
        for command in extra_commands:
            extra_output = clean_cli_output(run_command_with_paging(connection, command))
            if not extra_output or INVALID_PATTERN.search(extra_output):
                continue
            detected = extract_model(extra_output)
            if detected != "N/A":
                return detected
        return "N/A"

    def run(self, info: dict) -> dict:
        inventory_cache = info.get("hardware_inventory")
        if isinstance(inventory_cache, dict):
            cached = self._result_from_cache(inventory_cache)
            if cached is not None:
                return cached

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
                "display version,show system,show version,show system information",
            )
        )

        tried = []
        for command in commands:
            tried.append(command)
            output = clean_cli_output(run_command_with_paging(connection, command))
            if not output or INVALID_PATTERN.search(output):
                continue

            model = extract_model(output)
            version, firmware = extract_version_and_firmware(output)
            if model == "N/A":
                model = self._lookup_model_with_extras(connection)

            if model != "N/A" and version != "N/A":
                return self._format_result(model, version, firmware, command)

        tried_cmds = ", ".join(tried)
        return {
            "name": self.name,
            "passed": False,
            "details": (
                "Aucune sortie exploitable (commandes testées: "
                f"{tried_cmds})"
            ),
        }
