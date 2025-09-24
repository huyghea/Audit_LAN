"""Découverte des équipements réseau."""

from __future__ import annotations

import logging
import re
from typing import Dict, Iterable, Optional

from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException
from netmiko.ssh_autodetect import SSHDetect

from .connection import connect_device
from .parsers import clean_cli_output, extract_model, extract_version_and_firmware

LOGGER = logging.getLogger(__name__)

SUPPORTED_DRIVERS: tuple[str, ...] = (
    "hp_comware",
    "hp_procurve",
    "huawei",
    "aruba_os",
)
PROMPT_PATTERN = r"[>#\]]"
DEFAULT_MORE_TOKEN = "---- More ----"


class Shell:
    """Interface minimale pour exécuter des commandes sur un équipement."""

    def __init__(self, connection) -> None:
        self._connection = connection

    def send_command(self, command: str) -> str:
        try:
            return self._connection.send_command_timing(
                command,
                delay_factor=2,
                strip_prompt=True,
                strip_command=True,
            )
        except Exception as exc:  # pragma: no cover - dépend de netmiko
            raise RuntimeError(
                f"Échec de la commande '{command}': {exc}"
            ) from exc

    def disconnect(self) -> None:
        try:
            self._connection.disconnect()
        except Exception as exc:  # pragma: no cover - dépend de netmiko
            LOGGER.debug("Erreur à la déconnexion: %s", exc)


def _read_with_paging(connection, command: str) -> str:
    output = connection.send_command_timing(
        command,
        strip_prompt=True,
        strip_command=True,
    )
    if not output:
        return ""

    chunk = output
    while DEFAULT_MORE_TOKEN in chunk:
        chunk = connection.send_command_timing(
            " ",
            strip_prompt=True,
            strip_command=True,
        )
        output += chunk
    return output


def _autodetect_vendor(ip: str, username: str, password: str) -> Optional[str]:
    try:
        detector = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
            timeout=2,
        )
        detector.device_type_list = list(SUPPORTED_DRIVERS)
        vendor = detector.autodetect()
        if vendor in SUPPORTED_DRIVERS:
            LOGGER.info("Autodétection Netmiko: %s → %s", ip, vendor)
            return vendor
        LOGGER.warning("Autodétection hors périmètre: %s → %s", ip, vendor)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
        LOGGER.warning("Autodétection impossible pour %s: %s", ip, exc)
    except Exception as exc:  # pragma: no cover - dépend netmiko
        LOGGER.error("Erreur inattendue d'autodétection sur %s: %s", ip, exc)
    return None


def _disable_paging(connection, vendor: str) -> None:
    if vendor == "hp_comware":
        commands: Iterable[str] = (
            "screen-length 0 temporary disable",
            "screen-length 0",
        )
    elif vendor == "huawei":
        commands = ("screen-length 0 temporary", "screen-length 0")
    else:
        commands = ("no page",)

    for command in commands:
        try:
            connection.send_command(
                command,
                expect_string=PROMPT_PATTERN,
                strip_prompt=True,
                strip_command=True,
                read_timeout=2,
            )
        except Exception:  # pragma: no cover - dépend équipement
            continue


def _collect_device_info(
    vendor: str,
    connection,
    hostname: str,
) -> dict[str, str]:
    if vendor in {"hp_comware", "huawei"}:
        command = "display version"
    else:
        command = "show version"
    raw_version = _read_with_paging(connection, command)

    cleaned_output = clean_cli_output(raw_version)
    model = extract_model(cleaned_output)
    version, firmware = extract_version_and_firmware(cleaned_output)

    if vendor == "hp_comware" and (model == "N/A" or not model):
        try:
            manu_info = clean_cli_output(
                _read_with_paging(connection, "display device manuinfo")
            )
            model_match = re.search(
                r"^\s*DEVICE_NAME\s*:\s*(.+)",
                manu_info,
                re.MULTILINE,
            )
            if model_match:
                model = model_match.group(1).strip()
        except Exception:  # pragma: no cover - dépend équipement
            LOGGER.debug("Impossible de lire la manuinfo HP sur %s", hostname)

    if model == "N/A" or not model:
        try:
            modules = clean_cli_output(_read_with_paging(connection, "show module"))
            model_match = re.search(
                r"Chassis:\s*(.+?)\s+Serial Number",
                modules,
                re.MULTILINE,
            )
            if model_match:
                model = model_match.group(1).strip()
        except Exception:  # pragma: no cover - dépend équipement
            LOGGER.debug("Impossible de déduire le modèle via show module sur %s", hostname)

    if not firmware or firmware == "N/A":
        firmware_match = re.search(r"(KB|WC)\.\d+\.\d+\.\d+", cleaned_output)
        if firmware_match:
            firmware = firmware_match.group(0)

    if model == "N/A" or not model:
        model = hostname
    if not version or version == "N/A":
        version = "N/A"
    if not firmware:
        firmware = version if version != "N/A" else "N/A"

    return {
        "model": model,
        "version": version,
        "firmware": firmware,
        "command": command,
        "raw_output": cleaned_output,
    }


def discover_device(ip: str, username: str, password: str) -> Optional[Dict[str, object]]:
    vendor_hint = _autodetect_vendor(ip, username, password)
    drivers = list(SUPPORTED_DRIVERS)
    if vendor_hint and vendor_hint in drivers:
        drivers.remove(vendor_hint)
        drivers.insert(0, vendor_hint)

    for vendor in drivers:
        connection = connect_device(
            ip,
            username,
            password,
            device_type_override=vendor,
        )
        if connection is None:
            continue

        _disable_paging(connection, vendor)

        prompt = connection.find_prompt()
        hostname = re.sub(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "", prompt)

        inventory = _collect_device_info(vendor, connection, hostname)

        return {
            "ip": ip,
            "device_type": vendor,
            "hostname": hostname,
            "model": inventory.get("model", hostname),
            "firmware": inventory.get("firmware", "N/A"),
            "version": inventory.get("version", "N/A"),
            "hardware_inventory": inventory,
            "connection": connection,
            "shell": Shell(connection),
        }

    LOGGER.error("Découverte échouée pour %s", ip)
    return None
