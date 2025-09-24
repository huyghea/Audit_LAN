# ============================================================
# Audit ventilateurs sur équipements réseau (SSH)
# ============================================================
#
# Objectif (en une phrase) :
#   Vérifier l’état des ventilateurs (fans) sur une liste d’équipements réseau
#   en se connectant via SSH et en analysant les sorties CLI.
#
# Fonctionnement global :
#   - Lecture des IPs depuis un fichier CSV (colonne "ip").
#   - Connexion SSH via Netmiko sur chaque équipement.
#   - Exécution de commandes susceptibles d’afficher l’état des ventilateurs.
#   - Analyse de la sortie (regex) pour compter combien sont "Normal".
#   - Résultats affichés en console et alertes sauvegardées dans un fichier texte.
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler


# ============================================================
# Fonction : analyser_fan_output
# ------------------------------------------------------------
# Rôle :
#   - Recevoir la sortie brute (texte) d’une commande ventilateurs.
#   - Identifier les motifs indiquant l’état des ventilateurs.
#   - Retourner deux valeurs :
#       ok    = nombre de ventilateurs en "Normal"
#       total = nombre total de ventilateurs détectés
#
# Formats gérés :
#   1) Lignes avec mots-clés ("Normal", "Abnormal", "Faulty", "Absent").
#   2) Résumé du type "X / Y Fans in Failure State".
#   3) Ratio générique "X / Y" (OK / Total).
#
# Retour :
#   - (ok, total) si format reconnu
#   - (None, None) si analyse impossible
# ============================================================
def analyser_fan_output(output: str):
    # Découpe de la sortie en lignes
    lignes = output.strip().splitlines()

    # --- Cas 1 : analyse ligne par ligne (chaque ligne = 1 ventilateur) ---
    lignes_utiles = [
        l for l in lignes
        if re.search(r"(Normal|Abnormal|Faulty|Absent)", l, re.IGNORECASE)
    ]
    total = len(lignes_utiles)
    ok = sum(1 for l in lignes_utiles if re.search(r"Normal", l, re.IGNORECASE))

    if total > 0:
        return ok, total

    # --- Cas 2 : résumé "X / Y Fans in Failure State" ---
    m = re.search(r"(\d+)\s*/\s*(\d+)\s*Fans in Failure State", output)
    if m:
        ko, total = int(m.group(1)), int(m.group(2))
        return total - ko, total  # OK = Total - KO

    # --- Cas 3 : ratio générique "X / Y" ---
    m2 = re.search(r"(\d+)\s*/\s*(\d+)", output)
    if m2:
        ok, total = int(m2.group(1)), int(m2.group(2))
        return ok, total

    # --- Cas 4 : rien reconnu ---
    return None, None


# ============================================================
# Fonction : auditer
# ------------------------------------------------------------
# Rôle :
#   - Se connecter à l’équipement en SSH (Netmiko).
#   - Désactiver la pagination (si supportée).
#   - Exécuter une série de commandes ventilateurs.
#   - Analyser la sortie pour déterminer un état global :
#       * OK      → tous les ventilateurs sont normaux
#       * Aucun   → aucun ventilateur détecté (cas fanless ou OS atypique)
#       * KO      → un ou plusieurs ventilateurs en défaut/absents
#   - Ajouter les résultats dans la liste globale et consigner les alertes.
#
# Paramètres :
#   - ip        : adresse IP de l’équipement
#   - user/mdp  : identifiants SSH
#   - resultats : liste pour les résultats généraux
#   - alertes   : liste pour les anomalies
# ============================================================
def auditer(ip: str, user: str, mdp: str, resultats: list, alertes: list):
    device = {
        "device_type": "terminal_server",  # générique pour n'importe quel type d'equi
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 15,             # délai global (en secondes)
        "global_delay_factor": 2,  # ralentir si CLI lente
        "fast_cli": False          # privilégier la robustesse à la vitesse
    }

    try:
        with ConnectHandler(**device) as conn:
            # Tentative de désactivation de la pagination
            try:
                conn.send_command_timing("screen-length disable")  # Comware/HPE
            except Exception:
                pass

            # Commandes candidates selon OS
            commandes = [
                "display fan",      # Comware (HPE/H3C)
                "display device",   # Huawei
                "show system fans"  # Aruba
            ]

            ok, total, cmd_utilisee = None, None, None

            # On teste chaque commande jusqu’à trouver une sortie exploitable
            for cmd in commandes:
                sortie = conn.send_command_timing(cmd)
                ok, total = analyser_fan_output(sortie)
                if total is not None:
                    cmd_utilisee = cmd
                    break

            # --- Cas 1 : analyse impossible ---
            if total is None:
                resultats.append(f"[{ip}] Erreur : analyse impossible")
            # --- Cas 2 : aucun ventilateur détecté ---
            elif total == 0:
                resultats.append(
                    f"[{ip}] Aucun ventilateur détecté (0/0) [N/A] | Commande utilisée: {cmd_utilisee}"
                )
            # --- Cas 3 : tout est normal ---
            elif ok == total:
                resultats.append(
                    f"[{ip}] Ventilateurs OK ({ok}/{total}) [True] | Cmd: {cmd_utilisee} | "
                    f"Explication: tous les ventilateurs sont en état Normal"
                )
            # --- Cas 4 : anomalies détectées ---
            else:
                alerte = (
                    f"[{ip}] Problème ventilateurs ({ok}/{total}) [False] | Cmd: {cmd_utilisee} | "
                    f"Explication: au moins un ventilateur est en panne ou absent"
                )
                resultats.append(alerte)
                alertes.append(alerte)

    except Exception as e:
        # On capture toute erreur de connexion/commande et on continue avec les autres IPs
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction : main
# ------------------------------------------------------------
# Rôle :
#   - Demander les identifiants SSH à l’utilisateur.
#   - Lire la liste des IPs depuis un CSV (colonne "ip").
#   - Lancer l’audit en parallèle (thread par IP).
#   - Afficher tous les résultats.
#   - Sauvegarder les alertes dans un fichier si présentes.
# ============================================================
def main():
    print("=== Audit ventilateurs ===")

    # Saisie utilisateur
    user = input("Nom d'utilisateur SSH : ")
    mdp = getpass.getpass("Mot de passe SSH : ")

    # Lecture des IPs dans equipements.csv
    with open("equipements.csv") as f:
        ips = [r["ip"].strip() for r in csv.DictReader(f)]

    threads, resultats, alertes = [], [], []

    # Lancement d’un thread par IP
    for ip in ips:
        t = threading.Thread(target=auditer, args=(ip, user, mdp, resultats, alertes))
        t.start()
        threads.append(t)

    # Attente de fin de tous les threads
    for t in threads:
        t.join()

    # Résultats affichés
    print("\n--- Résultats ---")
    for r in resultats:
        print(r)

    # Sauvegarde des alertes dans un fichier dédié
    if alertes:
        with open("fan_audit_risques.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans fan_audit_risques.txt")


# ============================================================
# Entrée script
# ============================================================
if __name__ == "__main__":
    main()