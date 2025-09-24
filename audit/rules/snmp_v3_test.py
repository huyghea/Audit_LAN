"""Test SNMPv3 asynchrone."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from pysnmp.hlapi.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd as get_cmd_async,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from .base_rules import BaseAuditRule


AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
}
PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
}


async def _internal_test_snmp_v3(
    host: str,
    user: str,
    auth_key: str,
    priv_key: str,
    oid: str,
    port: int,
    auth_protocol_str: str,
    priv_protocol_str: str,
    timeout_val: int,
    retries_val: int,
) -> tuple[bool, str]:
    auth_proto_obj = AUTH_PROTOCOLS.get(
        auth_protocol_str.upper(),
        usmNoAuthProtocol,
    )
    priv_proto_obj = PRIV_PROTOCOLS.get(
        priv_protocol_str.upper(),
        usmNoPrivProtocol,
    )

    snmp_engine = SnmpEngine()

    try:
        transport_target = await UdpTransportTarget.create(
            (host, port),
            timeout=timeout_val,
            retries=retries_val,
        )

        response = await get_cmd_async(
            snmp_engine,
            UsmUserData(
                userName=user,
                authKey=auth_key,
                privKey=priv_key,
                authProtocol=auth_proto_obj,
                privProtocol=priv_proto_obj,
            ),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = response

        if error_indication:
            return False, f"SNMPv3 Error: {error_indication}"
        if error_status:
            error_msg = error_status.prettyPrint()
            if error_index and var_binds and 0 < int(error_index) <= len(var_binds):
                binding = var_binds[int(error_index) - 1][0].prettyPrint()
                error_msg += f" at {binding}"
            else:
                error_msg += f" at index {error_index}"
            return False, f"SNMPv3 Status Error: {error_msg}"

        results = [var_bind.prettyPrint() for var_bind in var_binds]
        if not results:
            return True, "SNMPv3 OK. No data returned for OID."
        return True, f"SNMPv3 OK. Response: {'; '.join(results)}"

    except TypeError as exc:  # pragma: no cover - dépend pysnmp
        message = str(exc)
        if (
            "got multiple values for argument" in message
            or "__init__" in message
            or ".create() to construct" in message
        ):
            return (
                False,
                "SNMPv3 API TypeError (UdpTransportTarget related): "
                f"{message}",
            )
        return False, f"SNMPv3 TypeError: {message}"
    except Exception as exc:  # pragma: no cover - dépend pysnmp
        return False, f"SNMPv3 Unexpected Exception: {exc}"


class SnmpV3CheckRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "snmp_v3_check"

    def run(self, info: Dict[str, Any]) -> Dict[str, Any]:
        ip = info.get("ip")
        if not ip:
            return {
                "passed": False,
                "details": "IP address missing from device info",
            }

        user = info.get("snmp_user")
        auth_key = info.get("snmp_auth_key")
        priv_key = info.get("snmp_priv_key")
        auth_proto_str = info.get(
            "snmp_auth_proto",
            self.config.get("auth_protocol", "SHA"),
        )
        priv_proto_str = info.get(
            "snmp_priv_proto",
            self.config.get("priv_protocol", "AES"),
        )

        if not all([user, auth_key, priv_key]):
            return {
                "passed": False,
                "details": (
                    "SNMPv3 credentials (snmp_user, snmp_auth_key, "
                    "snmp_priv_key) not found in info dict"
                ),
            }

        try:
            success, details = asyncio.run(
                _internal_test_snmp_v3(
                    ip,
                    str(user),
                    str(auth_key),
                    str(priv_key),
                    oid=self.config.get("oid", "1.3.6.1.2.1.1.3.0"),
                    port=int(self.config.get("port", 161)),
                    auth_protocol_str=str(auth_proto_str),
                    priv_protocol_str=str(priv_proto_str),
                    timeout_val=int(self.config.get("timeout", 5)),
                    retries_val=int(self.config.get("retries", 0)),
                )
            )
            return {"passed": success, "details": details}
        except RuntimeError as exc:  # pragma: no cover - dépend event loop
            return {
                "passed": False,
                "details": f"Asyncio runtime error: {exc}.",
            }
        except Exception as exc:  # pragma: no cover - dépend pysnmp
            return {
                "passed": False,
                "details": f"Error running SNMP check: {exc}",
            }
