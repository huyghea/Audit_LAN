# ============================================================
# Audit espace disque et firmwares (SSH)
# ============================================================
# Objectif :
#   - Se connecter en SSH à une liste d'équipements réseau
#   - Exécuter des commandes d’inventaire de la mémoire flash :
#         * Cisco : "dir" / "show flash"
#         * Huawei/Comware : "display flash"
#   - Extraire :
#         * capacité totale et espace libre
#         * liste des fichiers firmware (extensions .bin / .cc / .img / .ipe)
#   - Vérifier si l’espace libre est suffisant pour stocker le plus gros firmware détecté
#   - Produire un résumé par équipement et générer un fichier d’alertes si nécessaire
#
# Pré-requis :
#   - Fichier CSV "equipements.csv" avec une colonne "ip"
#   - Bibliothèques Python : netmiko, paramiko
#
# Notes :
#   - device_type = "terminal_server" (générique). Pour plus de robustesse,
#     remplacez-le par le type Netmiko adapté ("cisco_ios", "huawei", "hp_comware", etc.)
#   - Le script est multi-threads (un thread par IP).
# ============================================================

import re
import csv
import sys
import getpass
import threading
from typing import List, Tuple, Optional

from netmiko import ConnectHandler
from paramiko.ssh_exception import SSHException


# ============================================================
# Parsing : espace disque
# ------------------------------------------------------------
# Exemples de formats :
#   - '524288 KB total (173956 KB free)'
#   - '631960 KB total available (440092 KB free)'
#   - séparateurs de milliers possibles (ex: "1,234,567")
# Retour :
#   (total_str, libre_str, total_int, libre_int) ou None si non trouvé
# ============================================================
def extraire_disque(output: str) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    for line in output.splitlines():
        m = re.search(
            r"([\d,]+)\s*KB\s+total(?:\s+available)?\s*\(\s*([\d,]+)\s*KB\s+free",
            line,
            flags=re.IGNORECASE,
        )
        if m:
            total_str = m.group(1).replace(",", "")
            libre_str = m.group(2).replace(",", "")
            try:
                return total_str, libre_str, int(total_str), int(libre_str)
            except ValueError:
                continue
    return None, None, None, None


# ============================================================
# Parsing : firmwares
# ------------------------------------------------------------
# Recherche des binaires de firmware (.bin / .cc / .img / .ipe).
# Exemple de lignes :
#   - '-rw-    174,624,256  ...  AR650A_V300R021C10SPC100.cc'
#   - '123456789  some-image.bin'
# Stratégie :
#   - repère le nom de fichier
#   - tente d’extraire une taille numérique (format -rw- ou plus grand entier sur la ligne)
# ============================================================
def extraire_firmwares(output: str) -> List[Tuple[str, int]]:
    firmwares: List[Tuple[str, int]] = []

    for line in output.splitlines():
        low = line.lower()
        if not any(ext in low for ext in (".bin", ".cc", ".img", ".ipe")):
            continue

        m_file = re.search(r"(\S+\.(?:bin|cc|img|ipe))", line, re.IGNORECASE)
        if not m_file:
            continue

        # Taille associée
        m_size = re.search(r"-rw-\s+([\d,]+)", line)
        size_val: Optional[int] = None

        if m_size:
            try:
                size_val = int(m_size.group(1).replace(",", ""))
            except ValueError:
                size_val = None

        if size_val is None:
            candidates = [c for c in re.findall(r"([\d,]+)", line)]
            conv = []
            for c in candidates:
                try:
                    conv.append(int(c.replace(",", "")))
                except ValueError:
                    continue
            if conv:
                size_val = max(conv)

        if size_val is not None:
            firmwares.append((m_file.group(1), size_val))

    return firmwares


# ============================================================
# Exécution de commandes avec gestion de pagination
# ------------------------------------------------------------
# Certains OS affichent "---- More ----" ou "--More--"
# On supprime ces marqueurs et on envoie " " pour continuer.
# ============================================================
def run_cmd_all(conn, cmd: str) -> str:
    output = conn.send_command_timing(cmd)
    more_markers = ("---- More ----", "--More--", "More:", "<--- More --->")

    while any(marker in output for marker in more_markers):
        for marker in more_markers:
            output = output.replace(marker, "")
        output += conn.send_command_timing(" ")
    return output


# ============================================================
# Audit d’un équipement
# ------------------------------------------------------------
# Étapes :
#   - Connexion SSH
#   - Désactivation pagination (si supportée)
#   - Test des commandes ["dir", "show flash", "display flash"]
#   - Parsing de l’espace disque + firmwares
#   - Vérification espace suffisant vs plus gros firmware
#   - Ajout résultat + alerte si besoin
# ============================================================
def auditer(ip: str, user: str, mdp: str, resultats: List[str], alertes: List[str]) -> None:
    device = {
        "device_type": "terminal_server",  # ⚠️ remplacer si possible
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 30,
        "conn_timeout": 30,
        "banner_timeout": 30,
        "global_delay_factor": 3,
        "fast_cli": False,
    }

    commandes = ["dir", "show flash", "display flash"]

    try:
        with ConnectHandler(**device) as conn:
            # Tentative désactivation pagination
            for disable in (
                "screen-length 0 temporary",
                "screen-length disable",
                "no page",
                "terminal length 0",
            ):
                try:
                    conn.send_command_timing(disable)
                except Exception:
                    pass

            used_cmd, sortie = None, ""

            for cmd in commandes:
                sortie = run_cmd_all(conn, cmd).strip()
                if not sortie:
                    continue
                if any(e in sortie for e in ("Unrecognized", "Invalid", "Unknown command", "Error:")):
                    continue
                used_cmd = cmd
                break

            if not sortie:
                resultats.append(f"[{ip}] Erreur : aucune sortie reçue (commandes testées: {', '.join(commandes)})")
                return

            total_str, libre_str, total, libre = extraire_disque(sortie)
            firmwares = extraire_firmwares(sortie)

            # Cas 1 : espace libre + firmwares
            if (libre is not None) and firmwares:
                fw_nom, fw_taille = max(firmwares, key=lambda x: x[1])
                fw_kb = fw_taille / 1024
                est_ok = libre > fw_kb
                etat = "True" if est_ok else "False"
                explication = "espace suffisant" if est_ok else "espace insuffisant → risque upgrade impossible"
                ligne = (
                    f"[{ip}] OK={etat} | Libre: {libre_str} KB "
                    f"| Firmware: {fw_nom} ({fw_taille} B ≈ {fw_kb:.2f} KB) "
                    f"| Cmd: {used_cmd} | Explication: {explication}"
                )
                resultats.append(ligne)
                if not est_ok:
                    alertes.append(ligne)

            # Cas 2 : firmwares mais pas d’espace détecté
            elif (libre is None) and firmwares:
                fw_nom, fw_taille = max(firmwares, key=lambda x: x[1])
                fw_kb = fw_taille / 1024
                ligne = (
                    f"[{ip}] OK=False | Libre: NA "
                    f"| Firmware: {fw_nom} ({fw_taille} B ≈ {fw_kb:.2f} KB) "
                    f"| Cmd: {used_cmd} | Explication: impossible de vérifier l’espace libre"
                )
                resultats.append(ligne)
                alertes.append(ligne)

            # Cas 3 : espace libre détecté mais pas de firmware
            elif (libre is not None) and not firmwares:
                ligne = (
                    f"[{ip}] OK=True | Libre: {libre_str} KB "
                    f"| Firmware: NA | Cmd: {used_cmd} "
                    f"| Explication: aucun firmware détecté"
                )
                resultats.append(ligne)

            # Cas 4 : rien détecté
            else:
                ligne = f"[{ip}] Non détecté (pas d’espace ni firmware) | Cmd: {used_cmd or 'NA'}"
                resultats.append(ligne)

    except SSHException as e:
        resultats.append(f"[{ip}] Erreur SSH : {str(e)}")
    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Programme principal
# ------------------------------------------------------------
#   - Lecture IPs depuis equipements.csv
#   - Demande login/mdp
#   - Lancement threads
#   - Affichage résultats
#   - Écriture fichier d’alertes
# ============================================================
def main() -> None:
    print("=== Audit espace disque et firmwares (SSH) ===")

    user = input("Nom d'utilisateur : ").strip()
    mdp = getpass.getpass("Mot de passe : ")

    try:
        with open("equipements.csv", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if "ip" not in (reader.fieldnames or []):
                print("Erreur : CSV doit contenir une colonne 'ip'.")
                sys.exit(1)
            ips = [(r.get("ip") or "").strip() for r in reader]
            ips = [ip for ip in ips if ip]
    except FileNotFoundError:
        print("Erreur : fichier 'equipements.csv' introuvable.")
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lecture CSV : {e}")
        sys.exit(1)

    if not ips:
        print("Aucune IP à auditer (CSV vide ?)")
        sys.exit(0)

    threads: List[threading.Thread] = []
    resultats: List[str] = []
    alertes: List[str] = []

    for ip in ips:
        t = threading.Thread(target=auditer, args=(ip, user, mdp, resultats, alertes), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n=== Résultats ===")
    for r in resultats:
        print(r)

    if alertes:
        try:
            with open("firmware_alertes.txt", "w", encoding="utf-8") as f:
                for a in alertes:
                    f.write(a + "\n")
            print("\nAlerte(s) enregistrée(s) dans firmware_alertes.txt")
        except Exception as e:
            print(f"\nImpossible d’écrire le fichier d’alertes : {e}")


# ============================================================
if __name__ == "__main__":
    main()