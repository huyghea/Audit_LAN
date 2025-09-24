"""Registre des règles d'audit disponibles."""

from __future__ import annotations

import logging
from typing import Dict, Type

from .base_rules import BaseAuditRule
from .cpu_usage import CpuUsageRule
from .fan_health import FanHealthRule
from .hardware_inventory import HardwareInventoryRule
from .memory_usage import MemoryUsageRule
from .power_supply import PowerSupplyRule
from .snmp_trap_check import SnmpTrapCheckRule
from .storage_capacity import StorageCapacityRule
from .sysname import SysnameRule
from .tacacs import TacacsRule
from .temperature import TemperatureRule
from .transceiver_diagnostics import TransceiverDiagnosticsRule
from .uptime import UptimeRule

LOGGER = logging.getLogger(__name__)


def _safe_import_snmp_rule() -> Type[BaseAuditRule] | None:
    try:
        from .snmp_v3_test import SnmpV3CheckRule  # type: ignore

        return SnmpV3CheckRule
    except ModuleNotFoundError as exc:  # pragma: no cover - dépend des dépendances optionnelles
        LOGGER.warning("Règle SNMPv3 désactivée (module manquant: %s)", exc)
        return None


RULE_CLASSES: tuple[Type[BaseAuditRule], ...] = tuple(
    filter(
        None,
        (
            SysnameRule,
            TacacsRule,
            _safe_import_snmp_rule(),
            SnmpTrapCheckRule,
            CpuUsageRule,
            MemoryUsageRule,
            FanHealthRule,
            PowerSupplyRule,
            TemperatureRule,
            UptimeRule,
            HardwareInventoryRule,
            StorageCapacityRule,
            TransceiverDiagnosticsRule,
        ),
    )
)  # type: ignore[arg-type]


RULE_REGISTRY: Dict[str, Type[BaseAuditRule]] = {rule().name: rule for rule in RULE_CLASSES}


def get_rule_class(name: str) -> Type[BaseAuditRule]:
    try:
        return RULE_REGISTRY[name]
    except KeyError as exc:  # pragma: no cover - garde-fou
        raise KeyError(f"Règle inconnue: {name}") from exc
