#!/usr/bin/env python3
# audit/runner.py

import time
from .discovery import discover_device
from .rules.sysname import SysnameRule
from .rules.tacacs import TacacsRule
from .rules.snmp_v3_test import SnmpV3CheckRule
from .rules.snmp_trap_check import SnmpTrapCheckRule

ALL_RULES = {
    rule.name: rule
    for rule in (SysnameRule(), TacacsRule(), SnmpV3CheckRule(), SnmpTrapCheckRule())
}

def run_audit(ip: str, username: str, password: str, rules_to_run_list=None, snmp_credentials_from_main=None) -> dict:
    start_time = time.time()
    
    effective_rules = rules_to_run_list if rules_to_run_list is not None else list(ALL_RULES.values())
    
    result = {"ip": ip, "duration": 0, "hostname": "N/A", "model": "N/A", "firmware": "N/A"}
    for rule_obj in effective_rules:
        result[f"{rule_obj.name}_compliant"] = False
        result[f"{rule_obj.name}_details"] = "Not run or discovery failed"

    device_info_dict = None
    try:
        device_info_dict = discover_device(ip, username, password)
    except Exception as e:
        result["model"] = f"Discovery Error: {e}"
        result["duration"] = round(time.time() - start_time, 1)
        return result

    if device_info_dict and isinstance(device_info_dict, dict):
        result.update({
            "hostname": str(device_info_dict.get("hostname", "N/A")),
            "model":    str(device_info_dict.get("model", "N/A")),
            "firmware": str(device_info_dict.get("firmware", "N/A"))
        })

        # Injecter les credentials SNMP dans device_info_dict
        if snmp_credentials_from_main and isinstance(snmp_credentials_from_main, dict):
            device_info_dict.update(snmp_credentials_from_main)

        # Vérification explicite de la connexion
        connection_ssh = device_info_dict.get("connection")
        if connection_ssh:
            device_info_dict["shell"] = connection_ssh
        else:
            print(f"✗ No SSH connection available for {ip}")
            result["model"] = "No SSH connection"
            result["duration"] = round(time.time() - start_time, 1)
            return result

        for rule_obj in effective_rules:
            try:
                rule_result = rule_obj.run(device_info_dict)
                result[f"{rule_obj.name}_compliant"] = bool(rule_result.get("passed", False))
                result[f"{rule_obj.name}_details"] = str(rule_result.get("details", "Rule returned no details"))
            except Exception as e:
                print(f"ERROR: Rule '{rule_obj.name}' on {ip} raised an exception: {e}")
                result[f"{rule_obj.name}_compliant"] = False
                result[f"{rule_obj.name}_details"] = f"Rule execution error: {e}"

        if connection_ssh and hasattr(connection_ssh, 'disconnect'):
            try:
                connection_ssh.disconnect()
            except Exception as e:
                print(f"Error disconnecting SSH from {ip}: {e}")
    else:
        result["model"] = "Discovery Failed (device_info_dict is None or not a dict)"

    result["duration"] = round(time.time() - start_time, 1)
    return result