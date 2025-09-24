"""Fonctions utilitaires communes aux règles d'audit."""

from __future__ import annotations

import logging
import re
from typing import Iterable, List, Sequence

LOGGER = logging.getLogger(__name__)


MORE_TOKENS_DEFAULT: Sequence[str] = (
    "---- More ----",
    "--More--",
    "More:",
    "<--- More --->",
)

DEFAULT_DISABLE_PAGING_BY_VENDOR: dict[str, Sequence[str]] = {
    "huawei": ("screen-length disable", "screen-length 0 temporary"),
    "hp_comware": (
        "screen-length disable",
        "screen-length 0 temporary disable",
    ),
    "hp_procurve": ("no page",),
    "aruba_os": ("no page", "terminal length 0"),
    "default": ("screen-length disable", "no page", "terminal length 0"),
}


def normalize_list(value: str | Iterable[str], separator: str = ",") -> List[str]:
    """Normalise une liste issue d'une configuration."""

    if isinstance(value, str):
        items = [part.strip() for part in value.split(separator)]
    else:
        items = [str(part).strip() for part in value]
    return [item for item in items if item]


def resolve_disable_paging_commands(
    device_type: str | None,
    configured: str | Iterable[str] | None,
) -> List[str]:
    """Détermine les commandes adaptées pour désactiver la pagination."""

    if configured:
        commands = normalize_list(configured)
        if commands:
            return commands

    if device_type:
        vendor_commands = DEFAULT_DISABLE_PAGING_BY_VENDOR.get(device_type)
        if vendor_commands:
            return list(vendor_commands)

    return list(DEFAULT_DISABLE_PAGING_BY_VENDOR["default"])


def parse_rules_argument(raw: Iterable[str] | str | None) -> List[str]:
    """Convertit l'entrée CLI/configuration en liste de règles sans doublon."""

    if raw is None:
        return []

    if isinstance(raw, str):
        candidates = raw.split(",")
    else:
        candidates = []
        for element in raw:
            if element is None:
                continue
            candidates.extend(str(part) for part in str(element).split(","))

    cleaned: List[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        name = candidate.strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(key)
    return cleaned


_PAGING_ERROR_PATTERN = re.compile(
    r"(unrecognized|invalid|unknown\s+command|incomplete|syntax\s+error)",
    re.IGNORECASE,
)


def _is_error_output(output: str) -> bool:
    """Détermine si la sortie indique une commande invalide."""

    if not output:
        return False
    return bool(_PAGING_ERROR_PATTERN.search(output))


def disable_paging(connection, commands: Sequence[str]) -> None:
    """Désactive la pagination en évitant les répétitions inutiles."""

    if getattr(connection, "_audit_paging_disabled", False):
        return

    already_tried = getattr(connection, "_audit_disable_paging_attempts", set())
    updated = False

    for command in commands:
        normalized = command.strip().lower()
        if not normalized or normalized in already_tried:
            continue
        already_tried.add(normalized)
        updated = True
        try:
            output = connection.send_command_timing(command)
        except Exception:  # pragma: no cover - dépend de l'équipement
            continue
        if _is_error_output(output):
            continue
        setattr(connection, "_audit_paging_disabled", True)
        setattr(connection, "_audit_disable_paging_attempts", already_tried)
        return

    if updated:
        setattr(connection, "_audit_disable_paging_attempts", already_tried)


def run_command_with_paging(
    connection,
    command: str,
    more_tokens: Sequence[str] | None = None,
) -> str:
    """Exécute une commande en gérant les prompts "More"."""

    tokens = more_tokens or MORE_TOKENS_DEFAULT
    output = connection.send_command_timing(command)
    if not output:
        return ""
    while any(marker in output for marker in tokens):
        for marker in tokens:
            output = output.replace(marker, "")
        output += connection.send_command_timing(" ")
    return output


def first_successful_command(connection, commands: Sequence[str]) -> tuple[str | None, str]:
    """Tente une liste de commandes et retourne la première sortie exploitable."""

    for command in commands:
        try:
            output = run_command_with_paging(connection, command)
        except Exception as exc:  # pragma: no cover - dépend des équipements
            LOGGER.debug(
                "Commande '%s' en échec: %s",
                command,
                exc,
            )
            continue
        if not output or not output.strip():
            continue
        lowered = output.lower()
        if (
            "unrecognized" in lowered
            or "invalid" in lowered
            or "unknown command" in lowered
        ):
            continue
        return command, output
    return None, ""
