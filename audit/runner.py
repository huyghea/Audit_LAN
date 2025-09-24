"""Exécution centralisée des règles d'audit."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Iterable, List

from .config_loader import load_rule_config
from .discovery import discover_device
from .rules import RULE_REGISTRY
from .rules.base_rules import BaseAuditRule

LOGGER = logging.getLogger(__name__)


def instantiate_rules(rule_names: Iterable[str], config_dir: Path) -> List[BaseAuditRule]:
    instances = []
    for name in rule_names:
        if name not in RULE_REGISTRY:
            raise KeyError(f"Règle inconnue: {name}")
        rule_class = RULE_REGISTRY[name]
        config = load_rule_config(name, config_dir)
        instances.append(rule_class(config=config))
    return instances


def run_audit(
    ip: str,
    username: str,
    password: str,
    rules_to_run_list: Iterable[BaseAuditRule],
    snmp_credentials_from_main: dict | None = None,
) -> dict:
    start_time = time.time()

    result = {"ip": ip, "duration": 0, "hostname": "N/A", "model": "N/A", "firmware": "N/A"}
    for rule_obj in rules_to_run_list:
        result[f"{rule_obj.name}_compliant"] = False
        result[f"{rule_obj.name}_details"] = "Règle non exécutée"

    try:
        device_info = discover_device(ip, username, password)
    except Exception as exc:  # pragma: no cover - dépend de netmiko
        LOGGER.error("Découverte échouée pour %s: %s", ip, exc)
        result["model"] = f"Discovery Error: {exc}"
        result["duration"] = round(time.time() - start_time, 1)
        return result

    if not isinstance(device_info, dict):
        result["model"] = "Discovery Failed"
        result["duration"] = round(time.time() - start_time, 1)
        return result

    result.update(
        {
            "hostname": str(device_info.get("hostname", "N/A")),
            "model": str(device_info.get("model", "N/A")),
            "firmware": str(device_info.get("firmware", "N/A")),
        }
    )

    if snmp_credentials_from_main:
        device_info.update(snmp_credentials_from_main)

    connection = device_info.get("connection")
    if connection is None:
        LOGGER.warning("Aucune connexion SSH pour %s", ip)
        result["model"] = "No SSH connection"
        result["duration"] = round(time.time() - start_time, 1)
        return result

    device_info["shell"] = connection

    for rule_obj in rules_to_run_list:
        try:
            rule_result = rule_obj.run(device_info)
            result[f"{rule_obj.name}_compliant"] = bool(rule_result.get("passed", False))
            result[f"{rule_obj.name}_details"] = str(rule_result.get("details", ""))
        except Exception as exc:  # pragma: no cover - dépend équipement
            LOGGER.exception("Erreur lors de l'exécution de %s sur %s", rule_obj.name, ip)
            result[f"{rule_obj.name}_compliant"] = False
            result[f"{rule_obj.name}_details"] = f"Erreur de règle: {exc}"

    try:
        if hasattr(connection, "disconnect"):
            connection.disconnect()
    except Exception as exc:  # pragma: no cover - dépend netmiko
        LOGGER.debug("Erreur lors de la déconnexion de %s: %s", ip, exc)

    result["duration"] = round(time.time() - start_time, 1)
    return result
