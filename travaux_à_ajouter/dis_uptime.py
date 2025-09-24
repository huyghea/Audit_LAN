# ============================================================
# Audit uptime (temps de fonctionnement) des équipements réseau (SSH)
# ============================================================
#
# Objectif :
#   - Vérifier depuis combien de temps les équipements fonctionnent sans reboot.
#   - Détecter si un redémarrage récent (< 1 jour) s’est produit.
#   - Afficher aussi la raison du dernier reboot si l’OS le fournit.
#
# Fonctionnement global :
#   - Lecture du fichier "equipements.csv" (colonne obligatoire : ip).
#   - Connexion SSH via Netmiko.
#   - Exécution de commandes "version / system info" (selon OS).
#   - Extraction de l’uptime et éventuellement de la cause du dernier reboot.
#   - Conversion en secondes pour comparaison avec le seuil (1 jour).
#   - Affichage résultats et enregistrement des alertes dans un fichier.
#
# Notes :
#   - device_type par défaut = "terminal_server" (générique).
#     Peut être remplacé par "huawei", "cisco_ios", "hp_comware"…
#   - Formats supportés :
#       * "uptime is ..."
#       * "Uptime is ..."
#       * "Up Time : ..."
#   - Parsing de "Last reboot reason" / "Reboot Cause".
#   - Multi-threading : un thread par IP.
#
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler

# ------------------------------------------------------------
# Constantes (seuils)
# ------------------------------------------------------------
SEUIL_MIN_SECONDES = 86400  # 1 jour = 24h = 86400 secondes


# ============================================================
# Fonction : analyser_uptime
# ------------------------------------------------------------
# Rôle :
#   - Analyser la sortie CLI brute et extraire :
#       * uptime lisible (semaines/jours/heures/minutes)
#       * raison du reboot si présente
#       * uptime converti en secondes
# ============================================================
def analyser_uptime(output):
    uptime_str = None
    reboot_reason = "NA"

    # --- Recherche raison reboot ---
    m_reason = re.search(r"(Last\s+reboot\s+reason\s*:\s*(.+))|(Reboot\s+Cause\s*:\s*(.+))",
                         output, re.IGNORECASE)
    if m_reason:
        reboot_reason = (m_reason.group(2) or m_reason.group(4) or "NA").strip()

    # --- Recherche uptime ---
    m_uptime = re.search(r"\buptime\s+is\s+(.+)", output, re.IGNORECASE)
    if not m_uptime:
        m_uptime = re.search(r"\bUptime\s+is\s+(.+)", output, re.IGNORECASE)
    if not m_uptime:
        m_uptime = re.search(r"\bUp\s*Time\s*[:=]\s*(.+)", output, re.IGNORECASE)

    if m_uptime:
        uptime_str = m_uptime.group(1).strip()
        # Nettoyage pour éviter de capturer trop de texte
        uptime_str = re.split(r"\s{2,}(Memory|CPU|Base|Software|ROM)", uptime_str)[0].strip()

    # --- Conversion en secondes ---
    total_seconds = 0
    weeks = days = hours = minutes = 0
    if uptime_str:
        m_time = re.search(r"(?:(\d+)\s*weeks?)?\s*,?\s*"
                           r"(?:(\d+)\s*days?)?\s*,?\s*"
                           r"(?:(\d+)\s*hours?)?\s*,?\s*"
                           r"(?:(\d+)\s*minutes?)?",
                           uptime_str, re.IGNORECASE)
        if m_time:
            weeks = int(m_time.group(1) or 0)
            days = int(m_time.group(2) or 0)
            hours = int(m_time.group(3) or 0)
            minutes = int(m_time.group(4) or 0)
        else:
            m_days = re.search(r"(\d+)\s*days?", uptime_str, re.IGNORECASE)
            if m_days:
                days = int(m_days.group(1))

        total_seconds = weeks * 7 * 86400 + days * 86400 + hours * 3600 + minutes * 60

    uptime_fmt = (f"{weeks} weeks, {days} days, {hours} hours, {minutes} minutes"
                  if (weeks + days + hours + minutes) > 0 else None)

    return uptime_fmt, reboot_reason, total_seconds


# ============================================================
# Fonction : auditer un équipement
# ------------------------------------------------------------
# 1. Connexion SSH
# 2. Exécution de commandes version/system
# 3. Parsing de l’uptime + reboot reason
# 4. Vérification seuil (>= 1 jour)
# 5. Ajout résultat + alerte si nécessaire
# ============================================================
def auditer(ip, user, mdp, resultats, alertes):
    device = {
        "device_type": "terminal_server",  # type générique
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 15,
        "global_delay_factor": 2,
        "fast_cli": False
    }

    commandes = [
        "display version",         # Huawei / Comware
        "show version",            # Cisco / HP
        "show system information", # Aruba
        "show system"              # Aruba variante
    ]

    try:
        with ConnectHandler(**device) as conn:
            # Désactivation pagination (si supportée)
            try:
                conn.send_command_timing("screen-length disable")
            except:
                pass

            # Certains OS demandent "Press any key" → on force un retour
            banner = conn.read_channel()
            if "Press any key" in banner:
                conn.write_channel("\n")
                conn.read_channel()

            used_cmd = None
            uptime_str = None
            reboot_reason = "NA"
            total_seconds = 0

            # Essai des commandes jusqu’à résultat exploitable
            for cmd in commandes:
                out = conn.send_command_timing(cmd)
                if not out or "Invalid" in out or "Unrecognized" in out:
                    continue
                tmp_uptime, tmp_reason, tmp_seconds = analyser_uptime(out)
                if tmp_uptime:
                    used_cmd = cmd
                    uptime_str, reboot_reason, total_seconds = tmp_uptime, tmp_reason, tmp_seconds
                    break

            if not uptime_str:
                resultats.append(f"[{ip}] Uptime : Non détecté (aucune info trouvée)")
                return

            est_ok = total_seconds >= SEUIL_MIN_SECONDES
            etat = "True" if est_ok else "False"
            explication = ("uptime supérieur à 1 jour"
                           if est_ok else
                           "uptime trop court → suspicion reboot récent")

            ligne = (f"[{ip}] Uptime: {uptime_str} | "
                     f"Raison reboot: {reboot_reason} | "
                     f"Cmd: {used_cmd} [{etat}] | Explication: {explication}")
            resultats.append(ligne)

            if not est_ok:
                alertes.append(ligne)

    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction principale
# ------------------------------------------------------------
# Rôle :
#   - Charger les IPs depuis equipements.csv
#   - Demander identifiants SSH
#   - Lancer audit multi-thread
#   - Afficher résultats
#   - Sauvegarder alertes
# ============================================================
def main():
    print("=== Audit uptime équipements ===")

    user = input("Nom d'utilisateur : ")
    mdp = getpass.getpass("Mot de passe : ")

    with open("equipements.csv") as f:
        ips = [r["ip"].strip() for r in csv.DictReader(f)]

    threads, resultats, alertes = [], [], []

    for ip in ips:
        if not ip:
            continue
        t = threading.Thread(target=auditer, args=(ip, user, mdp, resultats, alertes))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n--- Résultats ---")
    for r in resultats:
        print(r)

    if alertes:
        with open("uptime_audit_risques.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans uptime_audit_risques.txt")


# ============================================================
# Entrée script
# ============================================================
if __name__ == "__main__":
    main()
