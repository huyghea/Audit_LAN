"""Contrôle des modules SFP et mesures optiques."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .base_rules import BaseAuditRule
from ..utils import disable_paging, normalize_list, run_command_with_paging


def parse_transceivers(output: str) -> List[Dict[str, object]]:
    blocks = re.finditer(
        r"(?P<port>(?:GigabitEthernet|Ten[- ]?GigabitEthernet|Forty[- ]?GigabitEthernet|Hundred[- ]?GigE)\S+)"
        r"\s+transceiver\s+diagnostic\s+information:\s*"
        r"(?P<info>.*?)(?=(?:GigabitEthernet|Ten[- ]?GigabitEthernet|Forty[- ]?GigabitEthernet|Hundred[- ]?GigE)|$)",
        output,
        re.IGNORECASE | re.DOTALL,
    )

    regex_value = re.compile(
        r"(Temperature|Voltage|Bias\s*Current|RX\s*Power|TX\s*Power)\s*[:=]\s*([-]?\d+(?:\.\d+)?)"
        r".*?(?:Threshold|Range|Warning)\s*[:=]?\s*([-]?\d+(?:\.\d+)?)\s*(?:to|\.{2})\s*([-]?\d+(?:\.\d+)?)",
        re.IGNORECASE | re.DOTALL,
    )

    transceivers: List[Dict[str, object]] = []
    for match in blocks:
        port = match.group("port")
        info = (match.group("info") or "").strip()
        present = True
        measurements: List[Tuple[str, float, float, float, bool]] = []

        if re.search(r"(transceiver\s+is\s+absent|Error:\s*The\s+transceiver\s+is\s+absent)", info, re.IGNORECASE):
            present = False
        else:
            for value_match in regex_value.finditer(info):
                metric = value_match.group(1).strip()
                try:
                    val = float(value_match.group(2))
                    vmin = float(value_match.group(3))
                    vmax = float(value_match.group(4))
                except ValueError:
                    continue
                ok = vmin <= val <= vmax
                measurements.append((metric, val, vmin, vmax, ok))
            if not measurements:
                present = bool(re.search(r"present", info, re.IGNORECASE))

        transceivers.append({"port": port, "present": present, "measurements": measurements})

    return transceivers


class TransceiverDiagnosticsRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "transceiver_diagnostics"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {"name": self.name, "passed": False, "details": "Connexion SSH indisponible"}

        disable_paging(
            connection,
            normalize_list(self.config.get("disable_paging", "screen-length disable")),
        )

        commands = normalize_list(
            self.config.get(
                "commands",
                "display transceiver diagnosis interface,display transceiver,show interfaces transceiver",
            )
        )

        all_alerts: List[str] = []

        for command in commands:
            output = run_command_with_paging(connection, command)
            if not output.strip():
                continue
            if "Invalid" in output or "Unrecognized" in output:
                continue

            transceivers = parse_transceivers(output)
            if not transceivers:
                continue

            absent = sum(1 for t in transceivers if not t["present"])
            present = sum(1 for t in transceivers if t["present"])
            details_parts = [f"SFP présents: {present}", f"absents: {absent}", f"commande: {command}"]

            for transceiver in transceivers:
                port = transceiver["port"]
                if not transceiver["present"]:
                    details_parts.append(f"{port}: absent")
                    continue
                measurements = transceiver["measurements"]
                if not measurements:
                    details_parts.append(f"{port}: présent sans mesure")
                    continue
                for metric, value, vmin, vmax, ok in measurements:
                    if not ok:
                        alert = f"{port} {metric}={value} (seuil {vmin}..{vmax})"
                        all_alerts.append(alert)
                        details_parts.append(f"ALERTE {alert}")

            passed = not all_alerts
            details = "; ".join(details_parts)
            if not passed:
                details += " - mesures hors plage"
            return {"name": self.name, "passed": passed, "details": details}

        return {"name": self.name, "passed": False, "details": "Aucune donnée transceiver disponible"}
