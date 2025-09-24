# ============================================================
# Audit température sur équipements réseau (SSH)
# ============================================================
#
# Objectif :
#   - Vérifier automatiquement les températures mesurées par les équipements réseau.
#   - Comparer ces mesures aux seuils définis par les constructeurs (warning / alarm / upper).
#   - Produire un état simple (OK / KO) et remonter des alertes si besoin.
#
# Fonctionnement global :
#   - Lecture d’un fichier CSV (equipements.csv) qui contient les IPs à auditer.
#   - Connexion SSH via Netmiko sur chaque IP.
#   - Exécution de commandes "température" selon l’OS (Huawei, Comware, Aruba…).
#   - Parsing de la sortie (tabulaire ou texte libre).
#   - Comparaison des valeurs relevées aux seuils.
#   - Affichage des résultats et enregistrement des anomalies dans un fichier.
#
# Notes :
#   - device_type Netmiko = "terminal_server" (générique).
#     Peut être remplacé par "huawei", "cisco_ios", "hp_comware", etc. pour plus de robustesse.
#   - Le parser sait gérer :
#       * Tableaux CLI (colonnes alignées par espaces)
#       * Formats texte simples ("Temp: 36 C, Warning: 62 C, Alarm: 75 C")
#   - Multithreading : un thread par IP pour accélérer l’audit.
#
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler


# ============================================================
# Fonctions utilitaires de parsing
# ------------------------------------------------------------
# Ces helpers aident à reconnaître la structure d’une sortie CLI :
#   - séparateurs de tableau
#   - prompts CLI
#   - colonnes alignées
# ============================================================

def _is_sep(line):
    """Retourne True si la ligne est un séparateur (ex: '----')."""
    return bool(re.match(r'^\s*-{3,}\s*$', line))

def _prompt(line):
    """Retourne True si la ligne ressemble à un prompt CLI (ex: '<Switch01>')."""
    return bool(re.match(r'^<.*?>$', line.strip()))

def _compute_cols(header_line: str):
    """
    Déduit les colonnes d’un tableau CLI aligné à l’espace à partir de l’en-tête.
    Retourne une liste [(nom_colonne, start, end)].
    """
    cols, n, i, in_col, start = [], len(header_line), 0, False, None
    while i < n:
        if not in_col:
            if header_line[i] != ' ':
                in_col, start = True, i
        else:
            if header_line[i] == ' ' and i + 1 < n and header_line[i+1] == ' ':
                end = i
                name = header_line[start:end].strip().lower()
                if name:
                    cols.append((name, start, end))
                while i < n and header_line[i] == ' ':
                    i += 1
                in_col, start = False, None
                continue
        i += 1
    if in_col and start is not None:
        name = header_line[start:].strip().lower()
        if name:
            cols.append((name, start, n))
    return cols

def _slice(line, start, end):
    """Retourne une sous-chaîne line[start:end], protégée contre les dépassements."""
    if start >= len(line):
        return ""
    return line[start:min(end, len(line))].strip()

def _find_header(lines):
    """
    Localise la ligne d’en-tête d’un tableau contenant des températures.
    Heuristiques :
      - Cherche "temperature", "temp(c)" ou "temp".
      - Vérifie qu’il y a au moins 2 colonnes séparées par espaces.
    """
    for i, ln in enumerate(lines):
        l = ln.lower()
        if "information" in l:
            continue
        if re.search(r'\btemperature\b', l) or "temp(c)" in l or re.search(r'\btemp\b', l):
            parts = re.split(r'\s{2,}', ln.strip())
            if len(parts) >= 2:
                return i
    return None

def _find_span(map_cols, keys):
    """
    Retrouve la colonne correspondant à une liste de clés (temperature, warning, alarm...).
    Retourne (start, end) si trouvé, sinon None.
    """
    for k in keys:
        k = k.lower()
        for name, span in map_cols.items():
            if k == name or k in name:
                return span
    return None


# ============================================================
# Parsing des sorties CLI
# ------------------------------------------------------------
# Deux stratégies :
#   1) Tableaux (colonnes alignées) → _parse_table
#   2) Textes libres → _parse_non_table
# ============================================================

def _parse_table(lines):
    """
    Parse un tableau CLI contenant les températures.
    Retourne :
      (liste_temps, seuil_lower, seuil_warning, seuil_alarm)
    """
    hi = _find_header(lines)
    if hi is None:
        return [], None, None, None

    cols = _compute_cols(lines[hi])
    if not cols:
        return [], None, None, None

    name_to_span = {name: (start, end) for name, start, end in cols}

    sp_temp  = _find_span(name_to_span, ["temperature", "temp", "temp(c)"])
    sp_lower = _find_span(name_to_span, ["lowerlimit", "lower"])
    sp_warn  = _find_span(name_to_span, ["warninglimit", "warning", "upper"])
    sp_alarm = _find_span(name_to_span, ["alarmlimit", "alarm", "shutdownlimit"])

    if sp_temp is None:
        return [], None, None, None

    temps, lowers, warns, alarms = [], [], [], []
    data_found = False

    for ln in lines[hi+1:]:
        s = ln.strip()
        if not s or _is_sep(s) or _prompt(s):
            continue
        data_found = True

        tf = _slice(ln, *sp_temp)
        m = re.search(r'-?\d+(?:\.\d+)?', tf)
        if m:
            temps.append(float(m.group(0)))

        for sp, target in [(sp_lower, lowers), (sp_warn, warns), (sp_alarm, alarms)]:
            if sp:
                sf = _slice(ln, *sp)
                mm = re.search(r'-?\d+(?:\.\d+)?', sf)
                if mm:
                    target.append(float(mm.group(0)))

    if not data_found:
        return [], None, None, None

    lower = min(lowers) if lowers else None
    warn  = min(warns)  if warns  else None
    alarm = min(alarms) if alarms else None
    return temps, lower, warn, alarm

def _parse_non_table(output: str):
    """
    Parse un format texte libre.
    Exemple : "Temp: 36 C, Warning: 62 C, Alarm: 75 C"
    """
    temps = []
    for m in re.finditer(r'(-?\d+(?:\.\d+)?)\s*°?\s*C', output, re.IGNORECASE):
        temps.append(float(m.group(1)))

    def grab(tag):
        m = re.search(fr'{tag}[^0-9-]*(-?\d+(?:\.\d+)?)\s*°?\s*C', output, re.IGNORECASE)
        return float(m.group(1)) if m else None

    warn = grab("warning") or grab("upper")
    return temps, grab("lower"), warn, grab("alarm")

def extract_all(output: str):
    """Choisit entre parsing tableau et parsing texte libre."""
    lines = output.splitlines()
    t, l, w, a = _parse_table(lines)
    if t or (l is not None or w is not None or a is not None):
        return t, l, w, a
    return _parse_non_table(output)


# ============================================================
# Fonction d’audit par IP
# ------------------------------------------------------------
# 1. Connexion SSH
# 2. Exécution de commandes températures
# 3. Parsing des résultats
# 4. Comparaison aux seuils
# 5. Retour OK / KO + alerte si nécessaire
# ============================================================

def auditer(ip, user, mdp, resultats, alertes):
    device = {
        "device_type": "terminal_server",  # générique
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 20,
        "global_delay_factor": 2,
        "fast_cli": False,
    }

    cmds = [
        "display temperature all",  # Huawei
        "display env",              # Comware
        "display environment",      # Aruba
    ]

    try:
        with ConnectHandler(**device) as conn:

            def disable_paging():
                for c in ("screen-length 0 temporary", "screen-length disable"):
                    conn.send_command_timing(c)

            for cmd in cmds:
                disable_paging()
                out = conn.send_command_timing(cmd)
                if not out or not out.strip():
                    continue

                lo = out.lower()
                if "unrecognized command" in lo or "invalid input" in lo:
                    continue

                temps, lower, warn, alarm = extract_all(out)

                if (("temperature" in lo or "temp(c)" in lo) and not temps):
                    resultats.append(f"[{ip}] Cmd: {cmd} | Pas de capteurs détectés")
                    return

                if not temps:
                    continue

                seuils = [v for v in (warn, alarm) if v is not None]
                seuil = min(seuils) if seuils else None
                ok = True if seuil is None else (max(temps) <= seuil)

                def fmt(v):
                    return f"{v:.1f}°C" if v is not None else "NA"

                ligne = (
                    f"[{ip}] Temp {'OK' if ok else 'KO'} | Mesures: {temps} | "
                    f"Lower: {fmt(lower)} | Warning: {fmt(warn)} | Alarm: {fmt(alarm)} | "
                    f"Seuil: {fmt(seuil)} | Cmd: {cmd} "
                    f"[{'True' if ok else 'False'}] | Explication: "
                    f"{'dans les limites' if ok else 'dépassement de seuil'}"
                )
                resultats.append(ligne)

                if not ok:
                    alertes.append(ligne)
                return

            resultats.append(f"[{ip}] Température : non détectée (aucune commande supportée)")

    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction principale
# ------------------------------------------------------------
# 1. Demande login/mot de passe
# 2. Lecture des IPs dans equipements.csv
# 3. Lancement threads
# 4. Affichage résultats
# 5. Sauvegarde alertes
# ============================================================

def main():
    print("=== Audit température ===")

    user = input("Nom d'utilisateur SSH : ")
    mdp = getpass.getpass("Mot de passe SSH : ")

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
        with open("temp_audit_alertes.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans temp_audit_alertes.txt")


# ============================================================
# Entrée script
# ============================================================
if __name__ == "__main__":
    main()