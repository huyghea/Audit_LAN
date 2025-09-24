#!/usr/bin/env python3
# audit/rules/snmp_v3_test.py

import asyncio
from pysnmp.hlapi.asyncio import (
    get_cmd as get_cmd_async, 
    SnmpEngine, 
    UsmUserData, 
    UdpTransportTarget,
    ContextData, 
    ObjectType, 
    ObjectIdentity,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, 
    usmAesCfb128Protocol,
    usmNoAuthProtocol, 
    usmNoPrivProtocol
)
from .base_rules import BaseAuditRule

async def _internal_test_snmp_v3(host, user, auth_key, priv_key, 
                                 oid='1.3.6.1.2.1.1.3.0 ', # sysUpTime.0
                                 auth_protocol_str="SHA", priv_protocol_str="AES",
                                 timeout_val=5, retries_val=0):
    auth_proto_obj = {
        'MD5': usmHMACMD5AuthProtocol,
        'SHA': usmHMACSHAAuthProtocol
    }.get(auth_protocol_str.upper(), usmNoAuthProtocol)

    priv_proto_obj = {
        'DES': usmDESPrivProtocol,
        'AES': usmAesCfb128Protocol
    }.get(priv_protocol_str.upper(), usmNoPrivProtocol)

    snmpEngine = SnmpEngine()
    
    try:
        transport_target_instance = await UdpTransportTarget.create((host, 161), timeout=timeout_val, retries=retries_val)
        
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd_async(
            snmpEngine,
            UsmUserData(userName=user, authKey=auth_key, privKey=priv_key,
                        authProtocol=auth_proto_obj, privProtocol=priv_proto_obj),
            transport_target_instance, 
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        if errorIndication:
            return False, f"SNMPv3 Error: {str(errorIndication)}"
        elif errorStatus:
            error_msg = errorStatus.prettyPrint()
            if errorIndex and varBinds and int(errorIndex) <= len(varBinds) and int(errorIndex) > 0:
                 error_msg += f" at {varBinds[int(errorIndex)-1][0].prettyPrint()}"
            else:
                 error_msg += f" at index {errorIndex}"
            return False, f"SNMPv3 Status Error: {error_msg}"
        else:
            res_details_list = []
            for varBind in varBinds:
                res_details_list.append(varBind.prettyPrint()) 
            
            if not res_details_list:
                return True, "SNMPv3 OK. No data returned for OID."
            return True, f"SNMPv3 OK. Response: {'; '.join(res_details_list)}"

    except TypeError as te:
        if 'got multiple values for argument' in str(te) or '__init__' in str(te) or '.create() to construct' in str(te):
            return False, f"SNMPv3 API TypeError (UdpTransportTarget related): {str(te)}"
        return False, f"SNMPv3 TypeError: {str(te)}"
    except Exception as e:
        return False, f"SNMPv3 Unexpected Exception: {str(e)}"


class SnmpV3CheckRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "snmp_v3_check"

    def run(self, info: dict) -> dict:
        ip = info.get("ip")
        if not ip:
            return {"passed": False, "details": "IP address missing from device info"}

        # Read SNMP credentials from the 'info' dictionary using standardized keys
        user = info.get("snmp_user")
        auth_key = info.get("snmp_auth_key")
        priv_key = info.get("snmp_priv_key")
        auth_proto_str = info.get("snmp_auth_proto", "SHA") # Use default if not provided
        priv_proto_str = info.get("snmp_priv_proto", "AES") # Use default if not provided

        if not all([user, auth_key, priv_key]):
             return {"passed": False, "details": "SNMPv3 credentials (snmp_user, snmp_auth_key, snmp_priv_key) not found in info dict"}
        
        try:
            success, details = asyncio.run(
                _internal_test_snmp_v3(
                    ip, user, auth_key, priv_key,
                    auth_protocol_str=auth_proto_str,
                    priv_protocol_str=priv_proto_str
                )
            )
            return {"passed": success, "details": details}
        except RuntimeError as e: # Ex: "asyncio.run() cannot be called from a running event loop"
            return {"passed": False, "details": f"Asyncio runtime error: {e}."}
        except Exception as e:
            return {"passed": False, "details": f"Error running SNMP check: {e}"}