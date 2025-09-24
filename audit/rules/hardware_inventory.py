"""Inventaire matériel simplifié."""

from __future__ import annotations

import re
from typing import Tuple

from .base_rules import BaseAuditRule
from ..utils import disable_paging, normalize_list, run_command_with_paging

CSI = re.compile(r"\x1B\[[0-9;?]*[ -/]*[@-~]")
ESC = re.compile(r"\x1B[@-Z\\-_]")
CTL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_output(text: str) -> str:
    if not text:
        return ""
    text = CSI.sub("", text)
    text = ESC.sub("", text)
    text = CTL.sub("", text)
    text = text.replace("\r", "")
    text = re.sub(r"^\s*Press any key.*$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    return text


def detect_model(text: str) -> str:
    t = clean_output(text)
    match = re.search(
        r"^(?:HPE|HP|H3C|Huawei|Aruba|Cisco)\s+([^\n]+?)\s+with\b",
        t,
        re.IGNORECASE | re.MULTILINE,
    )
    if match:
        base = match.group(1).strip()
        pn = re.search(r"\b(J[HL]\d{3,}[A-Z]?)\b", t, re.IGNORECASE)
        if pn:
            part = pn.group(0).upper()
            if part not in base:
                base = f"{base} {part}"
        base = re.sub(r"\s+(Switch|Router)\s*$", "", base, flags=re.IGNORECASE)
        return base

    explicit = re.search(
        r"(?:Product\s*Name|Model|Device\s*model|Device\s*type|BOARD\s*TYPE)\s*:\s*([^\n]+)",
        t,
        re.IGNORECASE,
    )
    if explicit:
        return explicit.group(1).strip()

    chassis = re.search(r"^\s*Chassis\s*:\s*([^\n]+)$", t, re.IGNORECASE | re.MULTILINE)
    if chassis:
        return chassis.group(1).strip()

    hi = re.search(r"\b([0-9]{3,4}.*?(?:HI|EI)[^\n]*)", t, re.IGNORECASE)
    if hi:
        return hi.group(1).strip()

    aruba = re.search(r"\b(2930F[-\w +]*)\b", t, re.IGNORECASE)
    if aruba:
        return f"Aruba {aruba.group(1)}"

    huawei = re.search(r"\b(AR\d{3,}[A-Z]?)\b", t, re.IGNORECASE)
    if huawei:
        return huawei.group(1).upper()

    family = re.search(r"\bS\d{4}[A-Z0-9\-]*\b", t, re.IGNORECASE)
    if family:
        return family.group(0).upper()

    hp = re.search(r"\bHP\s*(\d{3,4}\w*)\b", t, re.IGNORECASE)
    if hp:
        return f"HP {hp.group(1)}"

    software = re.search(r"^(.*Software.*)$", t, re.IGNORECASE | re.MULTILINE)
    if software:
        return software.group(1).strip()

    return "N/A"


def detect_version(text: str) -> Tuple[str, str]:
    t = clean_output(text)

    comware7 = re.search(
        r"Comware\s+Software,\s*Version\s*([0-9A-Za-z.\-]+)\s*,\s*Release\s*([0-9A-Za-z]+)",
        t,
        re.IGNORECASE,
    )
    if comware7:
        base = comware7.group(1).strip()
        release = comware7.group(2).strip()
        return base, f"{base}, Release {release}"

    comware5 = re.search(
        r"\bVersion\s*([0-9]+\.[0-9A-Za-z.]+)\s*,\s*Release\s*([0-9A-Za-z]+)",
        t,
        re.IGNORECASE,
    )
    if comware5:
        base = comware5.group(1).strip()
        release = comware5.group(2).strip()
        return base, f"{base}, Release {release}"

    vrp = re.search(r"\bVersion\s*([0-9A-Za-z.\-]+)\s*(\([^)]+\))", t, re.IGNORECASE)
    if vrp:
        base = vrp.group(1).strip()
        return base, f"{base} {vrp.group(2).strip()}"

    aruba = re.search(r"(?:Software\s+revision|Software\s+Version)\s*:\s*([^\n]+)", t, re.IGNORECASE)
    if aruba:
        base = aruba.group(1).strip()
        return base, base

    generic = re.search(r"\bVersion\s*:\s*([^\n]+)", t, re.IGNORECASE)
    if generic:
        full = generic.group(1).strip()
        prefix = re.match(r"([0-9A-Za-z.\-]+)", full)
        version = prefix.group(1).strip() if prefix else full
        return version, full

    return "N/A", "N/A"


class HardwareInventoryRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "hardware_inventory"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {"name": self.name, "passed": False, "details": "Connexion SSH indisponible"}

        disable_paging(
            connection,
            normalize_list(self.config.get("disable_paging", "screen-length disable,screen-length 0 temporary,no page")),
        )

        commands = normalize_list(
            self.config.get("commands", "display version,show system,show version,show system information")
        )

        primary_output = ""
        used_command = None
        tried = []
        for command in commands:
            tried.append(command)
            output = clean_output(run_command_with_paging(connection, command))
            if not output or re.search(r"(Invalid|Unrecognized|Incomplete input)", output, re.IGNORECASE):
                continue
            if not primary_output:
                primary_output = output
                used_command = command

        if not primary_output:
            return {
                "name": self.name,
                "passed": False,
                "details": f"Aucune sortie exploitable (commandes testées: {', '.join(tried)})",
            }

        model = detect_model(primary_output)
        version, firmware = detect_version(primary_output)

        if model == "N/A":
            extra_commands = normalize_list(
                self.config.get("extra_commands", "display device manuinfo,display device,show inventory")
            )
            for command in extra_commands:
                extra_output = clean_output(run_command_with_paging(connection, command))
                if not extra_output or re.search(r"(Invalid|Unrecognized|Incomplete input)", extra_output, re.IGNORECASE):
                    continue
                detected = detect_model(extra_output)
                if detected != "N/A":
                    model = detected
                    break

        details = (
            f"Modèle: {model} | Version: {version} | Firmware: {firmware}"
            + (f" via {used_command}" if used_command else "")
        )

        passed = model != "N/A" and version != "N/A"
        if not passed:
            details += " - informations partielles"

        return {"name": self.name, "passed": passed, "details": details}
