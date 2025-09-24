# ============================================================
# Audit Hardware (multi-constructeurs) via SSH
# ============================================================
#
# Objectif :
#   - Se connecter en SSH à des équipements réseau listés dans un fichier CSV
#   - Lancer des commandes "version / inventaire / système" selon le constructeur
#   - Nettoyer les sorties CLI (suppression couleurs, caractères spéciaux, bannières…)
#   - Extraire les infos essentielles :
#       * Modèle lisible (ex : Aruba 2930F JL258A, HP 5510 HI JH145A, Huawei AR651…)
#       * Version et Firmware (selon règles Comware5, Comware7, VRP, Aruba, Cisco…)
#   - Afficher les résultats pour chaque équipement
#   - Sauvegarder un fichier d’alertes si des informations sont manquantes ou si une erreur survient
#
# Notes :
#   - Netmiko est utilisé pour la connexion SSH.
#   - device_type = "terminal_server" (générique). Pour plus de robustesse,
#     remplacer par "huawei", "hp_comware", "cisco_ios", "aruba_os"… si connu.
#   - Parsing basé sur regex → souple et tolérant aux variations de format.
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler

# ============================================================
# Outils de nettoyage des sorties CLI
# ------------------------------------------------------------
# Suppriment les caractères parasites : séquences ANSI, couleurs, retours chariot
# ============================================================

# CSI = Control Sequence Introducer (codes couleurs, curseur…)
CSI = re.compile(r'\x1B\[[0-9;?]*[ -/]*[@-~]')
# ESC = séquences d’échappement simples
ESC = re.compile(r'\x1B[@-Z\\-_]')
# CTL = caractères de contrôle non imprimables (hors tabulation, saut de ligne…)
CTL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

def clean(text: str) -> str:
    """
    Nettoie la sortie CLI :
      - enlève séquences ANSI (couleurs, curseur…)
      - enlève caractères de contrôle
      - supprime les '\r' pour avoir une sortie lisible
      - retire les lignes de bannière ("Press any key…")
    """
    if not text:
        return ""
    t = CSI.sub('', text)
    t = ESC.sub('', t)
    t = CTL.sub('', t)
    t = t.replace('\r', '')
    t = re.sub(r'^\s*Press any key.*$', '', t, flags=re.IGNORECASE | re.MULTILINE)
    return t

def _strip(s: str) -> str:
    """strip() sécurisé : retourne '' si None."""
    return (s or "").strip()

def _find(rx_list, text, flags=0):
    """Teste une liste de regex et retourne le premier match trouvé."""
    for rx in rx_list:
        m = re.search(rx, text, flags)
        if m:
            return m
    return None

# ============================================================
# Détection du modèle
# ------------------------------------------------------------
# Cherche le modèle lisible (Aruba, Comware, Huawei, Cisco…)
# ============================================================

def detect_modele(text: str) -> str:
    t = clean(text)

    # Cas 1 : forme "Vendor + produit ... with ..."
    m = re.search(r'^(?:HPE|HP|H3C|Huawei|Aruba|Cisco)\s+([^\n]+?)\s+with\b',
                  t, re.IGNORECASE | re.MULTILINE)
    if m:
        base = _strip(m.group(1))
        pn = _find([r'\b(J[HL]\d{3,}[A-Z]?)\b'], t, re.IGNORECASE)  # Part Number
        if pn:
            pnv = pn.group(0).upper()
            if pnv not in base:
                base = f"{base} {pnv}"
        base = re.sub(r'\s+(Switch|Router)\s*$', '', base, flags=re.IGNORECASE)
        return base

    # Cas 2 : champs explicites (Product Name, Model…)
    m = _find([
        r'(?:Product\s*Name|Model|Device\s*model|Device\s*type|BOARD\s*TYPE)\s*:\s*([^\n]+)',
        r'^\s*Chassis\s*:\s*([^\n]+)$',
    ], t, re.IGNORECASE | re.MULTILINE)
    if m:
        return _strip(m.group(1))

    # Cas 3 : signatures Comware HI/EI
    m = re.search(r'\b([0-9]{3,4}.*?(?:HI|EI)[^\n]*)', t, re.IGNORECASE)
    if m:
        return _strip(m.group(1))

    # Cas 4 : Aruba 2930F
    m = re.search(r'\b(2930F[-\w +]*)\b', t, re.IGNORECASE)
    if m:
        return f"Aruba {m.group(1)}"

    # Cas 5 : routeurs Huawei AR
    m = re.search(r'\b(AR\d{3,}[A-Z]?)\b', t, re.IGNORECASE)
    if m:
        return m.group(1).upper()

    # Cas 6 : familles S5500/S5700
    m = re.search(r'\bS\d{4}[A-Z0-9\-]*\b', t, re.IGNORECASE)
    if m:
        return m.group(0).upper()

    # Cas 7 : HP 750x
    m = re.search(r'\bHP\s*(\d{3,4}\w*)\b', t, re.IGNORECASE)
    if m:
        return f"HP {m.group(1)}"

    # Cas 8 : fallback sur "Software ..."
    m = re.search(r'^(.*Software.*)$', t, re.IGNORECASE | re.MULTILINE)
    if m:
        return _strip(m.group(1))

    return "N/A"

# ============================================================
# Détection version & firmware
# ------------------------------------------------------------
# Applique des règles selon Comware5/7, VRP Huawei, Aruba…
# ============================================================

def detect_version_firmware(text: str) -> tuple[str, str]:
    t = clean(text)

    # Comware 7
    m = re.search(r'Comware\s+Software,\s*Version\s*([0-9A-Za-z.\-]+)\s*,\s*Release\s*([0-9A-Za-z]+)',
                  t, re.IGNORECASE)
    if m:
        base, rel = _strip(m.group(1)), _strip(m.group(2))
        return base, f"{base}, Release {rel}"

    # Comware 5
    m = re.search(r'\bVersion\s*([0-9]+\.[0-9A-Za-z.]+)\s*,\s*Release\s*([0-9A-Za-z]+)', t, re.IGNORECASE)
    if m:
        base, rel = _strip(m.group(1)), _strip(m.group(2))
        return base, f"{base}, Release {rel}"

    # Huawei VRP
    m = re.search(r'\bVersion\s*([0-9A-Za-z.\-]+)\s*(\([^)]+\))', t, re.IGNORECASE)
    if m:
        base = _strip(m.group(1))
        return base, f"{base} {m.group(2).strip()}"

    # Aruba
    m = re.search(r'(?:Software\s+revision|Software\s+Version)\s*:\s*([^\n]+)', t, re.IGNORECASE)
    if m:
        base = _strip(m.group(1))
        return base, base

    # Fallback
    m = re.search(r'\bVersion\s*:\s*([^\n]+)', t, re.IGNORECASE)
    if m:
        full = _strip(m.group(1))
        m2 = re.match(r'([0-9A-Za-z.\-]+)', full)
        version = _strip(m2.group(1)) if m2 else full
        return version, full

    return "N/A", "N/A"

# ============================================================
# Audit d’un équipement
# ------------------------------------------------------------
# - Connexion SSH
# - Essai commandes "version/system"
# - Parsing modèle, version, firmware
# - Résultat formaté + alerte si info manquante
# ============================================================

def auditer(ip, user, mdp, resultats, alertes):
    device = {
        "device_type": "terminal_server",  # type générique
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 25,
        "conn_timeout": 20,
        "global_delay_factor": 2,
        "fast_cli": False,
    }

    tried, used_cmd, primary_out = [], None, ""
    enrich_out = ""

    try:
        with ConnectHandler(**device) as conn:
            # Désactiver pagination (si supportée)
            for c in ("screen-length disable", "screen-length 0 temporary", "no page"):
                try:
                    conn.send_command_timing(c)
                except:
                    pass

            # Commandes principales
            palette = ["display version", "show system", "show version", "show system information"]
            for cmd in palette:
                out = clean(conn.send_command_timing(cmd))
                tried.append(cmd)
                if out and not re.search(r'(Invalid|Unrecognized|Incomplete input)', out, re.IGNORECASE):
                    if not primary_out:
                        primary_out, used_cmd = out, cmd

            if not primary_out:
                resultats.append(f"[{ip}] Erreur : aucune sortie exploitable (commands testées : {tried})")
                alertes.append(f"[{ip}] Aucune donnée hardware trouvée")
                return

            # Détection modèle
            modele = detect_modele(primary_out)
            if modele == "N/A":
                for ecmd in ("display device manuinfo", "display device", "show inventory"):
                    eout = clean(conn.send_command_timing(ecmd))
                    if eout and not re.search(r'(Invalid|Unrecognized|Incomplete input)', eout, re.IGNORECASE):
                        enrich_out = eout
                        em = detect_modele(enrich_out)
                        if em != "N/A":
                            modele = em
                            break

            # Détection version/firmware
            version, firmware = detect_version_firmware(primary_out)
            if version == "N/A" and enrich_out:
                version, firmware = detect_version_firmware(enrich_out)

            # Bloc de sortie formaté
            block = [
                "============================================================",
                f"IP: {ip}",
                f"Commande utilisée: {used_cmd}",
                f"Modèle: {modele}",
                f"Version: {version}",
                f"Firmware: {firmware}",
                "------------------------------------------------------------",
            ]
            resultats.append("\n".join(block))

            if modele == "N/A" or version == "N/A":
                alertes.append(f"[{ip}] Informations incomplètes (modèle/version)")

    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")
        alertes.append(f"[{ip}] {str(e)}")

# ============================================================
# Fonction principale
# ============================================================

def main():
    print("=== Audit Hardware (multi-constructeurs) ===")

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
        with open("hardware_audit_alertes.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans hardware_audit_alertes.txt")

# ============================================================
# Lancement
# ============================================================

if __name__ == "__main__":
    main()