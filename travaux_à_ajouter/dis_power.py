# ============================================================
# Audit alimentation sur équipements réseau (SSH)
# ============================================================
#
# Objectif (en une phrase) :
#   Vérifier l’état des alimentations électriques (PSU – Power Supply Units)
#   sur une liste d’équipements réseau accessibles en SSH.
#
# Fonctionnement global :
#   - Lecture des adresses IP dans un CSV (equipements.csv).
#   - Connexion SSH sur chaque équipement (via Netmiko).
#   - Exécution d’une ou plusieurs commandes connues ("display power", "show environment power", …).
#   - Analyse de la sortie texte pour déterminer combien d’alimentations sont :
#         * OK (fonctionnelles)
#         * Fault (défectueuses)
#         * Absent (emplacements vides)
#   - Production d’un état global par équipement :
#         * OK        → toutes les alimentations sont fonctionnelles
#         * Partiel   → au moins une alimentation manquante ou en défaut
#         * KO        → aucune alimentation en état de marche
#   - Résultats affichés en console et alertes enregistrées dans un fichier texte.
# Points importants :
#   - Type Netmiko utilisé : "terminal_server" (générique).
#   - Parsing basé sur des mots-clés courants ("OK", "Fault", "Absent").
#   - Multi-threading : un thread par IP pour accélérer l’audit sur de grands parcs.
#
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler


# ============================================================
# Fonction : analyser_power_output
# ------------------------------------------------------------
# Rôle :
#   - Lire la sortie brute d’une commande "power" (affichage CLI).
#   - Identifier les PSU par état (OK / Fault / Absent).
#   - Calculer un total et retourner les valeurs comptées.
#
# Méthodes utilisées :
#   1. Comptage ligne par ligne avec regex (ex: "OK", "Fault", "Absent").
#   2. Recherche de formats récapitulatifs (plus fiables si présents).
#   3. Retour d’un tuple (ok, fault, absent, total).
#
# Exemple de sortie CLI interprétée :
#   - "Power 1 : OK"
#   - "Power 2 : Fault"
#   - "Power 3 : Absent"
#
# Exemple de résumé interprété :
#   - "(1 fault(s), 1 absent(s), 2 OK)"
#   - "2 / 3 supply bays delivering power"
# ============================================================
def analyser_power_output(output: str):
    ok, fault, absent = 0, 0, 0

    # --- Étape 1 : lecture ligne par ligne ---
    for l in output.splitlines():
        if re.search(r"\b(Normal|OK|Present|Powered|Active)\b", l, re.IGNORECASE):
            ok += 1
        elif re.search(r"\b(Fault|Abnormal|Fail|Defect|Error)\b", l, re.IGNORECASE):
            fault += 1
        elif re.search(r"\b(Absent|Not Present|Missing)\b", l, re.IGNORECASE):
            absent += 1

    # --- Étape 2 : recherche d’un résumé explicite ---
    m = re.search(r"\((\d+)\s+fault\(s\),\s+(\d+)\s+absent\(s\),\s+(\d+)\s+OK\)", output)
    if m:
        fault, absent, ok = map(int, m.groups())

    # --- Étape 3 : format "X / Y supply bays delivering power" ---
    m2 = re.search(r"(\d+)\s*/\s*(\d+)\s*supply bays delivering power", output, re.IGNORECASE)
    if m2:
        ok = int(m2.group(1))
        total_detected = int(m2.group(2))
        absent = max(0, total_detected - ok)
        return ok, fault, absent, total_detected

    # Total = somme des trois états
    total = ok + fault + absent
    return ok, fault, absent, total


# ============================================================
# Fonction : auditer
# ------------------------------------------------------------
# Rôle :
#   - Se connecter en SSH sur l’équipement (IP).
#   - Essayer une liste de commandes liées à l’alimentation.
#   - Récupérer et analyser la sortie.
#   - Classer le résultat en OK / Partiel / KO.
#   - Ajouter le résumé dans les listes partagées.
#
# Paramètres :
#   - ip        → adresse IP de l’équipement.
#   - user/mdp  → identifiants SSH.
#   - resultats → liste de tous les résultats.
#   - alertes   → liste des cas critiques (Partiel, KO).
#
# Cas particuliers gérés :
#   - Commande non supportée ("Unrecognized", "Invalid").
#   - Équipement sans capteurs ("does not support power display").
#   - Analyse impossible (aucun PSU détecté).
# ============================================================
def auditer(ip: str, user: str, mdp: str, resultats: list, alertes: list):
    # Configuration de la connexion SSH via Netmiko
    device = {
        "device_type": "terminal_server",  # générique 
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 20,
        "global_delay_factor": 2,
        "fast_cli": False
    }

    # Commandes testées (adapter selon vos OS)
    commandes = [
        "display power",              # Huawei / Comware
        "show system power-supply",   # Aruba
        "show environment power",     # Cisco / HP
    ]

    try:
        with ConnectHandler(**device) as conn:
            # Désactivation de la pagination (différente selon OS)
            try:
                conn.send_command_timing("screen-length 0 temporary")  # Huawei
            except:
                try:
                    conn.send_command_timing("no page")  # Comware/H3C/HPE
                except:
                    pass

            sortie, used_cmd = "", None

            # Test des commandes une par une
            for cmd in commandes:
                sortie = conn.send_command_timing(cmd)
                if sortie and "Unrecognized" not in sortie and "Invalid" not in sortie:
                    used_cmd = cmd
                    break

            if not sortie:
                resultats.append(f"[{ip}] Erreur : aucune sortie reçue")
                return

            if "does not support power display" in sortie:
                resultats.append(f"[{ip}] Alimentation : Non disponible (pas de capteurs) | Cmd: {used_cmd}")
                return

            # Analyse de la sortie
            ok, fault, absent, total = analyser_power_output(sortie)

            if total == 0:
                resultats.append(f"[{ip}] Erreur : analyse impossible | Cmd: {used_cmd}")
                return

            details = f"({fault} fault(s), {absent} absent(s), {ok} OK)"

            # Détermination de l’état global
            if ok == total:
                ligne = (
                    f"[{ip}] Alimentation OK ({ok}/{total}) | {details} | Cmd: {used_cmd} "
                    f"[True] | Explication: toutes les alimentations sont fonctionnelles"
                )
                resultats.append(ligne)

            elif ok >= 1:
                ligne = (
                    f"[{ip}] Alimentation partielle ({ok}/{total}) | {details} | Cmd: {used_cmd} "
                    f"[False] | Explication: au moins une alimentation absente ou en défaut"
                )
                resultats.append(ligne)
                alertes.append(ligne)

            else:
                ligne = (
                    f"[{ip}] Alimentation KO (0/{total}) | {details} | Cmd: {used_cmd} "
                    f"[False] | Explication: aucune alimentation fonctionnelle → risque critique"
                )
                resultats.append(ligne)
                alertes.append(ligne)

    except Exception as e:
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction : main
# ------------------------------------------------------------
# Rôle :
#   - Demander login/mot de passe SSH.
#   - Charger les IP depuis le fichier equipements.csv.
#   - Lancer l’audit en parallèle (un thread par IP).
#   - Afficher les résultats.
#   - Écrire un fichier "power_audit_risques.txt" si alertes détectées.
# ============================================================
def main():
    print("=== Audit alimentation ===")

    user = input("Nom d'utilisateur SSH : ")
    mdp = getpass.getpass("Mot de passe SSH : ")

    with open("equipements.csv") as f:
        ips = [r["ip"].strip() for r in csv.DictReader(f)]

    threads, resultats, alertes = [], [], []

    # Un thread par IP
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
        with open("power_audit_risques.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans power_audit_risques.txt")


# ============================================================
# Entrée principale
# ============================================================
if __name__ == "__main__":
    main()