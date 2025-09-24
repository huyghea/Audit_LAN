# ============================================================
# Audit CPU sur équipements réseau (SSH)
# ============================================================
#
# Objectif :
#   - Vérifier automatiquement la charge CPU des équipements réseau.
#   - Extraire plusieurs métriques (5s, 10s, 1m, 5m, instantané… selon l’OS).
#   - Calculer moyenne et pic.
#   - Comparer aux seuils définis et produire des alertes si besoin.
#   - Consolider les résultats par site.
#
# Fonctionnement global :
#   - Lecture du fichier "equipements.csv" (colonnes : ip, site, device_type).
#   - Connexion SSH sur chaque équipement (Netmiko).
#   - Exécution de commandes CPU usuelles selon les OS.
#   - Parsing de la sortie (plusieurs formats gérés : Huawei, Comware, Cisco…).
#   - Calcul des moyennes et pics.
#   - Résultats affichés par équipement et par site.
#   - Écriture des alertes dans "cpu_audit_alertes.txt".
#
# Paramètres globaux :
#   - SEUIL_MOYENNE = 80 % (alerte si dépassé)
#   - SEUIL_PIC     = 90 % (alerte si dépassé)
#
# Notes :
#   - device_type par défaut : "terminal_server" (générique).
#     Peut être remplacé par "cisco_ios", "huawei", "hp_comware", etc.
#     via la colonne "device_type" dans le CSV.
#   - Multi-threading : un thread par IP pour paralléliser l’audit.
#   - Gestion des erreurs : exceptions SSH ou parsing capturées.
#
# ============================================================

import re
import csv
import sys
import getpass
import threading
from typing import List, Tuple, Optional, Dict
from collections import defaultdict

from netmiko import ConnectHandler
from paramiko.ssh_exception import SSHException

# ---------------------------
# Seuils globaux
# ---------------------------
SEUIL_MOYENNE = 80.0   # si la moyenne dépasse 80% → alerte
SEUIL_PIC = 90.0       # si un pic dépasse 90% → alerte

# Activer un journal Netmiko (utile debug, crée "session_<ip>.log")
SESSION_LOG = False


# ============================================================
# Parsing des sorties CLI CPU
# ------------------------------------------------------------
# Rôle :
#   - Reconnaître différents formats de sortie (Huawei, Comware, Cisco…).
#   - Extraire les valeurs numériques (% CPU).
#   - Retourner la liste des valeurs + leurs étiquettes (5s, 1m, 5m…).
# ============================================================
def extraire_cpu(output: str) -> Tuple[List[float], List[str], Optional[str]]:
    """
    Analyse la sortie CPU et extrait des valeurs (%).
    Retourne :
      - vals   : liste de valeurs CPU
      - labels : étiquettes (Now, 5s, 1m…)
      - source : type de format détecté ("control", "generic", "idle")
    """
    # ----- Cas Huawei (bloc "Control Plane") -----
    bloc_control = re.search(r"Control\s+Plane(.*?)(?=Data\s+Plane|$)", output,
                             re.IGNORECASE | re.DOTALL)
    if bloc_control:
        bloc = bloc_control.group(1)
        m_now = re.search(r"CPU\s*Usage:\s*([\d.]+)\s*%", bloc, re.IGNORECASE)
        now_val = float(m_now.group(1)) if m_now else None
        m_hist = re.search(r"ten\s*seconds:\s*([\d.]+)%.*?one\s*minute:\s*([\d.]+)%.*?five\s*minutes:\s*([\d.]+)%",
                           bloc, re.IGNORECASE | re.DOTALL)
        if m_hist:
            hist_vals = [float(m_hist.group(1)), float(m_hist.group(2)), float(m_hist.group(3))]
            labels = ["10s", "1m", "5m"]
            if now_val is not None:
                return [now_val] + hist_vals, ["Now"] + labels, "control"
            return hist_vals, labels, "control"

    # ----- Cas Comware/générique "in last ..." -----
    m = re.search(r'(\d+(?:\.\d+)?)%\s*in\s*last\s*5\s*seconds.*?'
                  r'(\d+(?:\.\d+)?)%\s*in\s*last\s*1\s*minute.*?'
                  r'(\d+(?:\.\d+)?)%\s*in\s*last\s*5\s*minutes',
                  output, re.IGNORECASE | re.DOTALL)
    if m:
        return [float(m.group(1)), float(m.group(2)), float(m.group(3))], ["5s", "1m", "5m"], "generic"

    # ----- Variante textuelle "Five seconds / One minute ..." -----
    m2 = re.search(r'Five\s*seconds:\s*(\d+(?:\.\d+)?)%.*?One\s*minute:\s*(\d+(?:\.\d+)?)%.*?Five\s*minutes:\s*(\d+(?:\.\d+)?)%',
                   output, re.IGNORECASE | re.DOTALL)
    if m2:
        return [float(m2.group(1)), float(m2.group(2)), float(m2.group(3))], ["5s", "1m", "5m"], "generic"

    # ----- Format "idle XX%" → charge = 100 - idle -----
    m3 = re.search(r'CPU\s*Usage.*?idle[^0-9]*?(\d+(?:\.\d+)?)\s*%', output,
                   re.IGNORECASE | re.DOTALL)
    if m3:
        idle = float(m3.group(1))
        load = 100.0 - idle
        return [load], ["Now"], "idle"

    return [], [], None


# ============================================================
# Exécution commande avec gestion pagination
# ============================================================
def _run_cmd_with_paging(conn, cmd: str) -> str:
    """
    Exécute une commande CLI et gère les "More" (pagination).
    Envoie des espaces tant que nécessaire.
    """
    out = conn.send_command_timing(cmd)
    if not out:
        return ""
    more_markers = ("---- More ----", "--More--", "More:", "<--- More --->")
    while any(marker in out for marker in more_markers):
        for marker in more_markers:
            out = out.replace(marker, "")
        out += conn.send_command_timing(" ")
    return out


def relever_cpu(conn) -> Tuple[List[float], List[str], Optional[str], Optional[str]]:
    """
    Essaie plusieurs commandes CPU selon l’OS.
    Retourne (vals, labels, commande utilisée, type de format).
    """
    commandes = [
        "display cpu-usage",   # Huawei / Comware
        "display cpu",         # Variante
        "show cpu",            # Cisco/HP
        "show processes cpu",  # Cisco IOS
        "show processes cpu history",  # Cisco historique
    ]
    for cmd in commandes:
        try:
            out = _run_cmd_with_paging(conn, cmd)
        except Exception:
            continue
        if not out.strip():
            continue
        vals, labels, source = extraire_cpu(out)
        if vals:
            return vals, labels, cmd, source
    return [], [], None, None


# ============================================================
# Fonction : auditer un équipement
# ------------------------------------------------------------
# Rôle :
#   - Connexion SSH à l’équipement.
#   - Récupération des valeurs CPU.
#   - Calcul moyenne et pic.
#   - Comparaison aux seuils.
#   - Ajout résultat et alerte éventuelle.
#   - Agrégation par site.
# ============================================================
def auditer(ip: str, site: str, user: str, mdp: str,
            resultats: List[str], alertes: List[str],
            agr_site: Dict[str, Dict[str, List[float]]],
            device_type_csv: Optional[str] = None) -> None:

    device_type = (device_type_csv or "").strip() or "terminal_server"
    device = {
        "device_type": device_type,
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 25,
        "global_delay_factor": 2,
        "fast_cli": False,
    }
    if SESSION_LOG:
        device["session_log"] = f"session_{ip}.log"

    try:
        with ConnectHandler(**device) as conn:
            # Désactivation pagination (selon OS)
            for disable in ("screen-length 0 temporary", "screen-length disable",
                            "no page", "terminal length 0"):
                try:
                    conn.send_command_timing(disable)
                except Exception:
                    pass

            vals, labels, cmd, source = relever_cpu(conn)
            if not vals:
                resultats.append(f"[{ip}] Erreur : CPU non détecté")
                return

            moyenne = sum(vals) / len(vals)
            pic = max(vals)

            # Agrégation par site
            if site:
                agr_site[site]["moys"].append(moyenne)
                agr_site[site]["maxs"].append(pic)

            # Construction résultat
            parts = [f"[{ip}] CPU"]
            for lbl, v in zip(labels, vals):
                parts.append(f"{lbl}: {v:.1f}%")
            parts.append(f"Moy: {moyenne:.1f}%")
            parts.append(f"Max: {pic:.1f}%")
            if cmd:
                parts.append(f"Cmd: {cmd}")
            if source:
                parts.append(f"Source: {source}")

            # Vérification seuils
            etat = "True"
            explication = "charge dans les limites"
            if moyenne > SEUIL_MOYENNE or pic > SEUIL_PIC:
                etat = "False"
                explication = "charge CPU critique → risque de saturation"
                alertes.append(" | ".join(parts) + f" | [{etat}] | Explication: {explication}")

            parts.append(f"[{etat}]")
            parts.append(f"Explication: {explication}")
            resultats.append(" | ".join(parts))

    except SSHException as e:
        resultats.append(f"[{ip}] Erreur SSH : {str(e)}")
    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction principale
# ------------------------------------------------------------
# Rôle :
#   - Lire equipements.csv.
#   - Demander identifiants.
#   - Lancer audits en parallèle.
#   - Afficher résultats + résumé par site.
#   - Sauvegarder alertes.
# ============================================================
def main() -> None:
    print("=== Audit CPU ===")
    user = input("Nom d'utilisateur : ").strip()
    mdp = getpass.getpass("Mot de passe : ")

    # Lecture CSV
    try:
        with open("equipements.csv", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if "ip" not in (reader.fieldnames or []):
                print("Erreur : 'equipements.csv' doit contenir une colonne 'ip'.")
                sys.exit(1)
            rows = list(reader)
    except FileNotFoundError:
        print("Erreur : fichier 'equipements.csv' introuvable.")
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lecture CSV : {e}")
        sys.exit(1)

    threads: List[threading.Thread] = []
    resultats: List[str] = []
    alertes: List[str] = []
    agr_site: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: {"moys": [], "maxs": []})

    # Lancement threads
    for row in rows:
        ip = (row.get("ip") or "").strip()
        if not ip:
            continue
        site = (row.get("site") or "").strip()
        device_type_csv = (row.get("device_type") or "").strip()
        t = threading.Thread(target=auditer,
                             args=(ip, site, user, mdp, resultats, alertes, agr_site, device_type_csv),
                             daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # Résultats détaillés
    print("\n=== Résultats ===")
    for r in sorted(resultats, key=lambda s: s.split("]")[0] if "]" in s else s):
        print(r)

    # Résumé par site
    if agr_site:
        print("\n=== Résumé par site ===")
        for site, data in agr_site.items():
            if not data["moys"]:
                continue
            site_moy = sum(data["moys"]) / len(data["moys"])
            site_max = max(data["maxs"]) if data["maxs"] else 0.0
            print(f"- {site or 'N/A'} → Moy: {site_moy:.1f}% | Max observé: {site_max:.1f}%")

    # Sauvegarde alertes
    if alertes:
        try:
            with open("cpu_audit_alertes.txt", "w", encoding="utf-8") as f:
                for a in alertes:
                    f.write(a + "\n")
            print("\nAlerte(s) enregistrée(s) dans cpu_audit_alertes.txt")
        except Exception as e:
            print(f"\nImpossible d’écrire fichier alertes : {e}")


# ============================================================
if __name__ == "__main__":
    main()
