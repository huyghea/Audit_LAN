#!/usr/bin/env python3
# audit/discovery.py

import re
from netmiko.ssh_autodetect import SSHDetect
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException
from .connection import connect_device

def get_full_output(conn, cmd, more_token="---- More ----"):
    output = ""
    chunk = conn.send_command_timing(cmd, strip_prompt=True, strip_command=True)
    output += chunk
    while more_token in chunk:
        chunk = conn.send_command_timing(" ", strip_prompt=True, strip_command=True)
        output += chunk
    return output

class Shell:
    """
    Classe représentant une interface shell pour exécuter des commandes sur l'équipement.
    """
    def __init__(self, connection):
        self.connection = connection

    def send_command(self, command):
        """
        Envoie une commande via la connexion et retourne la sortie.
        """
        try:
            output = self.connection.send_command_timing(command, delay_factor=2, strip_prompt=True, strip_command=True)
            return output
        except Exception as e:
            raise RuntimeError(f"Failed to execute command '{command}': {e}")

    def disconnect(self):
        """
        Déconnecte la session SSH.
        """
        try:
            self.connection.disconnect()
        except Exception as e:
            print(f"Error disconnecting shell: {e}")

def discover_device(ip, username, password):
    drivers = ["hp_comware", "hp_procurve", "huawei", "aruba_os"]
    prompt_pattern = r"[>#\]]"

    best = None
    try:
        guesser = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
            timeout=2
        )
        guesser.device_type_list = drivers
        best = guesser.autodetect()
        print(f"→ Autodetected {ip} as {best}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"✗ Autodetect failed on {ip}: {e}")
    except Exception as e:
        print(f"✗ Unexpected autodetect error on {ip}: {e}")

    if best not in drivers:
        best = None

    seq = drivers.copy()
    if best:
        seq.remove(best)
        seq.insert(0, best)

    for vendor in seq:
        conn = connect_device(ip, username, password, device_type_override=vendor)
        if not conn:
            continue

        # Désactiver la pagination
        if vendor == "hp_comware":
            disables = ["screen-length 0 temporary disable", "screen-length 0"]
        elif vendor == "huawei":
            disables = ["screen-length 0 temporary", "screen-length 0"]
        else:
            disables = ["no page"]

        for cmd in disables:
            try:
                conn.send_command(
                    cmd,
                    expect_string=prompt_pattern,
                    strip_prompt=True,
                    strip_command=True,
                    read_timeout=2
                )
            except Exception:
                pass

        raw_prompt = conn.find_prompt()
        hostname = re.sub(r'^[^A-Za-z0-9]+|[^A-Za-z0-9]+$', '', raw_prompt)

        # Récupérer les informations de version et modèle
        raw = get_full_output(conn, "show version" if vendor in ("aruba_os", "hp_procurve") else "display version")

        # === 3Com ===
        if "3Com Corporation" in raw and "Switch 7750 Software Version" in raw:
            model = "Switch 7750"
            m = re.search(r"Switch 7750 Software Version\s+([^\s]+)", raw)
            firmware = m.group(1) if m else ""

        elif vendor == "huawei":
            # Recherche du modèle pour les équipements Huawei V1 et V2
            m_v2 = re.search(r"HUAWEI\s+CloudEngine\s+(\S+)", raw, re.MULTILINE)  # Pour les V2
            m_v1 = re.search(r"HUAWEI\s+([\w\-]+)\s+Routing Switch", raw, re.MULTILINE)  # Pour les V1
            model = m_v2.group(1) if m_v2 else (m_v1.group(1) if m_v1 else "Inconnu")

            # Recherche de la version du firmware
            m = re.search(r"Version\s+([\d\.]+)\s*\(([^)]+)\)", raw, re.IGNORECASE)
            firmware = f"{m.group(1)} ({m.group(2)})" if m else ""

        elif vendor == "hp_comware":
            m_model = re.search(r"^\s*HP\s+(\d{5})\s+uptime", raw, re.MULTILINE)
            m_fw = re.search(r"Comware Software,\s*Version\s*([\d\.]+),\s*Release\s*([\w\d]+)", raw)
            if m_model and m_fw:
                model = f"HP {m_model.group(1)}"
                firmware = f"{m_fw.group(1)}, Release {m_fw.group(2)}"
            else:
                m_750x = re.search(r"^\s*HP\s+(\d{4})\s+uptime", raw, re.MULTILINE)
                m_fw2 = re.search(r"Comware Software,\s*Version\s*([\d\.]+),\s*Feature\s*([\w\d\-]+)", raw)
                if m_750x and m_fw2:
                    model = f"HP {m_750x.group(1)}"
                    firmware = f"{m_fw2.group(1)}, Feature {m_fw2.group(2)}"
                else:
                    m_fw3 = re.search(r"Comware Software,\s*Version\s*([\d\.]+),\s*Release\s*([\w\d]+)", raw)
                    firmware = f"{m_fw3.group(1)}, Release {m_fw3.group(2)}" if m_fw3 else ""
                    try:
                        manu = get_full_output(conn, "display device manuinfo")
                        m_model3 = re.search(r"^\s*DEVICE_NAME\s*:\s*(.+)", manu, re.MULTILINE)
                        model = m_model3.group(1).strip() if m_model3 else hostname
                    except Exception:
                        model = hostname

        else:
            m = re.search(r"(KB|WC)\.\d+\.\d+\.\d+", raw)
            firmware = m.group(0) if m else ""

            try:
                mod_out = conn.send_command(
                    "show module",
                    expect_string=prompt_pattern,
                    strip_prompt=True,
                    strip_command=True,
                    read_timeout=5
                )
                m2 = re.search(r"Chassis:\s*(.+?)\s+Serial Number", mod_out, re.MULTILINE)
                model = m2.group(1).strip() if m2 else hostname
            except Exception:
                model = hostname

        # Retourner les informations découvertes
        return {
            "ip":          ip,
            "device_type": vendor,
            "hostname":    hostname,
            "model":       model,
            "firmware":    firmware,
            "connection":  conn,  # Assurez-vous que la connexion est incluse
            "shell":       Shell(conn)
        }

    print(f"✗ Discovery failed on {ip}")
    return None
