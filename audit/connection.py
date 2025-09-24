#!/usr/bin/env python3
# audit/connection.py

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

def connect_device(ip, username, password, device_type_override=None):
    """
    vendor: (obsolète ici, on ignore)
    device_type_override: le driver Netmiko exact à utiliser si non-None.
    """
    if device_type_override:
        device_type = device_type_override
    else:
        device_type = "generic"

    print(f"→ [connect_device] Trying '{device_type}' on {ip}…")
    device = {
        "device_type": device_type,
        "host":        ip,
        "username":    username,
        "password":    password,
        "timeout":     10,
        "fast_cli":    False,
    }
    try:
        conn = ConnectHandler(**device)
        print(f"✓ [connect_device] Connected to {ip} as {device_type}")
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"✗ [connect_device] Connection failed to {ip} ({device_type}): {e}")
        return None
    except Exception as e:
        print(f"✗ [connect_device] Unexpected error for {ip}: {e}")
        return None
