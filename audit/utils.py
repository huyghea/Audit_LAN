"""Fonctions utilitaires communes aux règles d'audit."""

from __future__ import annotations

import logging
from typing import Iterable, List, Sequence

LOGGER = logging.getLogger(__name__)


MORE_TOKENS_DEFAULT: Sequence[str] = (
    "---- More ----",
    "--More--",
    "More:",
    "<--- More --->",
)


def normalize_list(value: str | Iterable[str], separator: str = ",") -> List[str]:
    """Normalise une liste issue d'une configuration."""

    if isinstance(value, str):
        items = [part.strip() for part in value.split(separator)]
    else:
        items = [str(part).strip() for part in value]
    return [item for item in items if item]


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


def disable_paging(connection, commands: Sequence[str]) -> None:
    """Désactive la pagination sur la connexion Netmiko fournie."""

    for command in commands:
        try:
            connection.send_command_timing(command)
        except Exception:  # pragma: no cover - dépend de l'équipement
            continue


def run_command_with_paging(connection, command: str, more_tokens: Sequence[str] | None = None) -> str:
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
            LOGGER.debug("Commande '%s' en échec: %s", command, exc)
            continue
        if not output or not output.strip():
            continue
        lowered = output.lower()
        if "unrecognized" in lowered or "invalid" in lowered or "unknown command" in lowered:
            continue
        return command, output
    return None, ""
