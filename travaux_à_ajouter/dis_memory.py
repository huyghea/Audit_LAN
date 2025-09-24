# ============================================================
# Audit d'utilisation mémoire sur équipements réseau (via SSH)
# ============================================================
#
# Objectif (en une phrase) :
#   Se connecter en SSH à une liste d'équipements  (fournie dans un CSV ),
#   exécuter une commande qui affiche l'utilisation mémoire, en extraire un
#   pourcentage, comparer à un seuil (85%), et produire un compte-rendu.
#
# Entrées :
#   - Fichier "equipements.csv" 
#   - Identifiants SSH saisis au clavier (login + mot de passe masqué)
#
# Sorties :
#   - Affichage en console d’une ligne par équipement (OK, Alerte ou Erreur)
#   - Fichier "memoire_audit_risques.txt" (créé seulement si des alertes)
#
# Comportement clé :
#   - Tente plusieurs commandes connues pour récupérer la mémoire (en fonction de type de l'equipement)
#   - Prend le *premier* pourcentage détecté dans la sortie (limitation assumée)
#   - Seuil d’alerte par défaut : 85% (modifiable)
#   - Lance un thread par équipement pour accélérer l’audit
# ============================================================

import re                # Recherche de motifs (regex) dans du texte
import csv               # Lecture du fichier CSV des équipements
import getpass           # Saisie du mot de passe en mode masqué
import threading         # Exécution parallèle (un thread par équipement)
from netmiko import ConnectHandler  # Connexion SSH simplifiée (librairie Netmiko)
from typing import Optional, List   # Aide à la lecture (annotations de type)

# ------ Paramètres métier modifiables facilement (sans toucher à la logique) ------
SEUIL_MEMOIRE = 85.0  # % à partir duquel on considère que l’usage mémoire est élevé

# Commandes candidates pour afficher la mémoire (ordre = priorité d’essai)
# Remarque : adapter/étendre selon vos OS. L’audit s’arrête dès qu’un % est trouvé.
COMMANDES_MEMOIRE: List[str] = [
    "display memory",       # Huawei/Comware (classique) / Aruba
    "display memory-usage"  # Variante (ex. Huawei AR651)
    # Exemples à ajouter selon besoin :
    # "display system resource",
    # "show processes memory",   # Cisco IOS(e)
    # "show memory",             # IOS classique / autres
]


# ============================================================
# Fonction : extraire_pourcentage
# ------------------------------------------------------------
# Rôle :
#   Parcourir une chaîne (sortie CLI brute) pour trouver un pourcentage “xx%”.
#
# Pourquoi cette approche simple ?
#   Les commandes et formats de sortie varient selon les constructeurs/versions.
#   Chercher un motif générique “nombre + %” permet de couvrir vite un large périmètre.
#
# Retour :
#   - float (ex.: 73.0) si trouvé
#   - None si aucun pourcentage détecté
#
# Pour affiner (ex. ne capter que la mémoire) :
#   - Chercher une ligne contenant un mot-clé puis le % :
#       re.search(r"(?i)memory.*?(\d+(?:\.\d+)?)\s*%", output)
#     (le (?i) rend la recherche insensible à la casse ; le .*? est non-gourmand)
# ============================================================
def extraire_pourcentage(output: str) -> Optional[float]:
    # Regex simple : “un entier ou décimal” suivi de “%”, avec espaces possibles
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", output)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            # Très rare : la capture n’est pas convertible ; on considère “non trouvé”
            return None
    return None


# ============================================================
# Fonction : auditer
# ------------------------------------------------------------
# Rôle (en 4 étapes) :
#   1) Ouvrir une session SSH vers l’IP fournie
#   2) Exécuter plusieurs commandes possibles jusqu’à trouver un pourcentage
#   3) Comparer le pourcentage au seuil (SEUIL_MEMOIRE)
#   4) Renseigner des messages lisibles dans “resultats” et “alertes”
#
# Paramètres :
#   - ip        : adresse IP de l’équipement cible
#   - user/mdp  : identifiants SSH
#   - resultats : liste partagée pour *tous* les messages (OK, Alerte, Erreur)
#   - alertes   : liste partagée pour *uniquement* les cas >= seuil
# ============================================================
def auditer(ip: str, user: str, mdp: str, resultats: List[str], alertes: List[str]) -> None:
    # Paramétrage Netmiko (timeouts un peu tolérants pour CLIs lentes)
    device = {
        "device_type": "terminal_server",  # À adapter si vous connaissez le type exact
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 15,             # Délai max d’attente I/O (secondes)
        "global_delay_factor": 2,  # Ralentit un peu Netmiko si la CLI répond lentement
        "fast_cli": False          # Privilégie la robustesse à la vitesse
    }

    try:
        # Gestionnaire de contexte = ouverture/fermeture auto de la session SSH
        with ConnectHandler(**device) as conn:
            # 1) Désactiver la pagination si possible (sinon on ignore l’erreur)
            try:
                conn.send_command_timing("screen-length disable")
            except Exception:
                pass  # Certains OS ne connaissent pas la commande, ce n’est pas bloquant

            # 2) Essayer chaque commande jusqu’à obtenir un pourcentage
            taux: Optional[float] = None
            cmd_utilisee: Optional[str] = None

            for cmd in COMMANDES_MEMOIRE:
                # send_command_timing est plus permissif sur la détection de prompt
                sortie = conn.send_command_timing(cmd)
                taux = extraire_pourcentage(sortie)
                if taux is not None:
                    cmd_utilisee = cmd
                    break  # On s’arrête au premier résultat exploitable

            # 3) Interpréter le résultat et formater un message lisible
            if taux is None:
                # Cas où aucune des commandes n’a donné un pourcentage exploitable
                resultats.append(f"[{ip}] Erreur : analyse impossible (aucun % détecté)")
                return

            if taux < SEUIL_MEMOIRE:
                # Utilisation mémoire sous contrôle : statut OK
                resultats.append(
                    f"[{ip}] Utilisation mémoire OK: {taux:.1f}% [True] | "
                    f"Commande: {cmd_utilisee} | Explication: sous le seuil (<{SEUIL_MEMOIRE:.0f}%)"
                )
            else:
                # Dépassement du seuil : on ajoute à la fois aux résultats et aux alertes
                alerte = (
                    f"[{ip}] Attention, mémoire élevée: {taux:.1f}% [False] | "
                    f"Commande: {cmd_utilisee} | Explication: au-dessus du seuil (≥{SEUIL_MEMOIRE:.0f}%)"
                )
                resultats.append(alerte)
                alertes.append(alerte)

    except Exception as e:
        # Toute exception (auth, réseau, prompt inattendu…) est capturée ici
        # → l’échec d’un équipement n’empêche pas les autres d’être audités.
        resultats.append(f"[{ip}] Erreur : {str(e)}")


# ============================================================
# Fonction : main()
# ------------------------------------------------------------
# Rôle :
#   - Demander les identifiants SSH
#   - Charger la liste d’IP depuis le CSV "equipements.csv"
#   - Lancer un thread par IP
#   - Afficher la synthèse et, en cas d’alertes, écrire un fichier “risques”
#
# Points d’attention :
#   - La durée dépend du nombre d’équipements et des timeouts réseau.
#   - L’ordre d’affichage final peut sembler aléatoire (lié au parallélisme).
#   - Un fichier “memoire_audit_risques.txt” est créé seulement s’il y a des alertes.
# ============================================================
def main() -> None:
    print("=== Audit mémoire (réseau) ===")

    # 1) Saisie des identifiants (mot de passe non affiché à l’écran)
    user = input("Nom d'utilisateur SSH : ")
    mdp = getpass.getpass("Mot de passe SSH : ")

    # 2) Ouverture du CSV et extraction des IP
    with open("equipements.csv", newline="") as f:
        reader = csv.DictReader(f)
        ips = [r["ip"].strip() for r in reader if r.get("ip")]

    if not ips:
        print("Aucune IP trouvée dans equipements.csv (colonne requise : 'ip').")
        return

    # 3) Préparation des structures partagées entre threads
    threads: List[threading.Thread] = []
    resultats: List[str] = []  # Toutes les lignes de synthèse (OK / Alerte / Erreur)
    alertes: List[str] = []    # Uniquement les cas au-dessus du seuil

    # 4) Démarrage d’un thread par équipement
    for ip in ips:
        t = threading.Thread(target=auditer, args=(ip, user, mdp, resultats, alertes), daemon=True)
        t.start()
        threads.append(t)

    # 5) Synchronisation : attendre que tous les threads aient terminé
    for t in threads:
        t.join()

    # 6) Affichage de la synthèse
    print("\n--- Résultats ---")
    for r in resultats:
        print(r)

    # 7) Si des alertes existent, on les persiste dans un fichier texte
    if alertes:
        with open("memoire_audit_risques.txt", "w", newline="") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans memoire_audit_risques.txt")


# ============================================================
# Point d’entrée du script
# ============================================================
if __name__ == "__main__":
    main()