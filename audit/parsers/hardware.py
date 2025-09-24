"""Utilitaires de parsing pour l'inventaire matériel."""

from __future__ import annotations

import re
from typing import Tuple

CSI = re.compile(r"\x1B\[[0-9;?]*[ -/]*[@-~]")
ESC = re.compile(r"\x1B[@-Z\\-_]")
CTL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
BANNER = re.compile(r"^\s*Press any key.*$", re.IGNORECASE | re.MULTILINE)


def clean_cli_output(text: str) -> str:
    """Nettoie une sortie CLI des séquences de contrôle et bannières."""

    if not text:
        return ""
    cleaned = CSI.sub("", text)
    cleaned = ESC.sub("", cleaned)
    cleaned = CTL.sub("", cleaned)
    cleaned = cleaned.replace("\r", "")
    cleaned = BANNER.sub("", cleaned)
    return cleaned


def extract_model(text: str) -> str:
    """Détermine un modèle lisible à partir d'une sortie CLI."""

    if not text:
        return "N/A"
    t = clean_cli_output(text)

    patterns = [
        r"^(?:HPE|HP|H3C|Huawei|Aruba|Cisco)\s+([^\n]+?)\s+with\b",
        r"(?:Product\s*Name|Model|Device\s*model|Device\s*type|BOARD\s*TYPE)\s*:\s*([^\n]+)",
        r"^\s*Chassis\s*:\s*([^\n]+)$",
        r"\b([0-9]{3,4}.*?(?:HI|EI)[^\n]*)",
        r"\b(2930F[-\w +]*)\b",
        r"\b(AR\d{3,}[A-Z]?)\b",
        r"\bS\d{4}[A-Z0-9\-]*\b",
        r"\bHP\s*(\d{3,4}\w*)\b",
        r"^\s*(Switch\s+7750)\s+Software\s+Version",
    ]
    for pattern in patterns:
        match = re.search(pattern, t, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if pattern == patterns[0]:
                pn = re.search(r"\b(J[HL]\d{3,}[A-Z]?)\b", t, re.IGNORECASE)
                if pn:
                    part = pn.group(0).upper()
                    if part not in value:
                        value = f"{value} {part}"
                value = re.sub(r"\s+(Switch|Router)\s*$", "", value, flags=re.IGNORECASE)
            if pattern == patterns[4]:
                value = f"Aruba {value}"
            if pattern == patterns[8]:
                return "Switch 7750"
            return value

    software_line = re.search(r"^(.*Software.*)$", t, re.IGNORECASE | re.MULTILINE)
    if software_line:
        return software_line.group(1).strip()

    return "N/A"


def extract_version_and_firmware(text: str) -> Tuple[str, str]:
    """Détecte la version et la chaîne firmware à partir d'une sortie CLI."""

    if not text:
        return "N/A", "N/A"
    t = clean_cli_output(text)

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

    aruba = re.search(
        r"(?:Software\s+revision|Software\s+Version)\s*:\s*([^\n]+)",
        t,
        re.IGNORECASE,
    )
    if aruba:
        base = aruba.group(1).strip()
        return base, base

    three_com = re.search(
        r"Switch\s+7750\s+Software\s+Version\s+([^\s]+)",
        t,
        re.IGNORECASE,
    )
    if three_com:
        version = three_com.group(1).strip()
        return version, version

    generic = re.search(r"\bVersion\s*:\s*([^\n]+)", t, re.IGNORECASE)
    if generic:
        full = generic.group(1).strip()
        prefix = re.match(r"([0-9A-Za-z.\-]+)", full)
        version = prefix.group(1).strip() if prefix else full
        return version, full

    return "N/A", "N/A"
