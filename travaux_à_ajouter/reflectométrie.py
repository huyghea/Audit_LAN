# ============================================================
# Audit SFP / Transceivers (multi-constructeurs) via SSH
# ============================================================
# Objectif :
#   - Se connecter en SSH à une liste d’équipements réseau (IPs depuis un CSV)
#   - Exécuter des commandes “transceiver / optics” selon l’OS (Comware/H3C/HP, Huawei, Cisco/Aruba…)
#   - Parser la sortie CLI par port pour déterminer :
#         * Présence ou absence du module (present / absent)
#         * Mesures : Température, Voltage, Bias Current, RX Power, TX Power
#           + seuils min/max associés (dans la plage / hors plage)
#   - Produire un rapport lisible par équipement + un résumé global
#   - Consigner les alertes en cas de mesures hors plage
#
# Points clés :
#   - device_type Netmiko utilisé = "terminal_server" (générique).
#     Remplacez-le par "huawei", "cisco_ios", "hp_comware", "aruba_os_switch", … si connu,
#     pour plus de robustesse et de rapidité.
#   - Parsing basé sur regex : tolérance aux variations de libellés et de formats multi-lignes.
#   - Multi-threading : un thread par IP → accélère l’audit.
# ============================================================

import re
import csv
import getpass
import threading
from netmiko import ConnectHandler


# ============================================================
# Parsing des transceivers
# ------------------------------------------------------------
# Rôle :
#   - Découper la sortie CLI en blocs (un bloc par port)
#   - Déterminer si un module est présent/absent
#   - Extraire les mesures + seuils et évaluer si la valeur est OK
#
# Retour :
#   Liste de dicts de la forme :
#     { "port": <nom>, "present": <bool>, "mesures": [(metric, val, vmin, vmax, ok), ...] }
# ============================================================
def extraire_transceivers(output):
    transceivers = []

    # Motif de découpe des blocs (GigabitEthernet, TenGigabitEthernet, FortyGigabitEthernet, HundredGigE…)
    regex_bloc = re.compile(
        r"(?P<port>(?:GigabitEthernet|Ten[- ]?GigabitEthernet|Forty[- ]?GigabitEthernet|Hundred[- ]?GigE)\S+)"
        r"\s+transceiver\s+diagnostic\s+information:\s*"
        r"(?P<info>.*?)(?=(?:GigabitEthernet|Ten[- ]?GigabitEthernet|Forty[- ]?GigabitEthernet|Hundred[- ]?GigE)|$)",
        re.IGNORECASE | re.DOTALL,
    )

    # Motif d’une mesure + seuils (tolérant sur "Threshold/Range/Warning" et séparateur "to/..")
    regex_val = re.compile(
        r"(Temperature|Voltage|Bias\s*Current|RX\s*Power|TX\s*Power)\s*[:=]\s*([-]?\d+(?:\.\d+)?)"
        r".*?(?:Threshold|Range|Warning)\s*[:=]?\s*([-]?\d+(?:\.\d+)?)\s*(?:to|\.{2})\s*([-]?\d+(?:\.\d+)?)",
        re.IGNORECASE | re.DOTALL,
    )

    # Découpe et analyse des blocs
    for m in regex_bloc.finditer(output):
        port = m.group("port")
        info = (m.group("info") or "").strip()
        present, mesures = False, []

        # Cas : module explicitement absent
        if re.search(r"(transceiver\s+is\s+absent|Error:\s*The\s+transceiver\s+is\s+absent)", info, re.IGNORECASE):
            present = False
        else:
            # Si au moins une mesure est trouvée → module considéré comme présent
            for v in regex_val.finditer(info):
                present = True
                metric = v.group(1).strip()
                try:
                    val = float(v.group(2))
                    vmin = float(v.group(3))
                    vmax = float(v.group(4))
                    ok = (vmin <= val <= vmax)
                    mesures.append((metric, val, vmin, vmax, ok))
                except Exception:
                    # Valeur non parseable → on ignore cette mesure
                    continue

        transceivers.append({"port": port, "present": present, "mesures": mesures})

    return transceivers


# ============================================================
# Audit d’un équipement (par IP)
# ------------------------------------------------------------
# Étapes :
#   - Connexion SSH (Netmiko)
#   - Désactivation pagination (si supportée)
#   - Exécution des commandes candidates
#   - Parsing et synthèse (présence/mesures par port)
#   - Mise à jour des résultats et des stats globales
# ============================================================
def auditer(ip, user, mdp, resultats, alertes, stats_globales):
    device = {
        "device_type": "terminal_server",  # générique 
        "host": ip,
        "username": user,
        "password": mdp,
        "timeout": 15,
        "global_delay_factor": 2,
        "fast_cli": False,
    }

    bloc_resultats = []  # Bloc texte de sortie pour cet équipement

    try:
        with ConnectHandler(**device) as conn:
            # Tentative de désactivation de la pagination
            try:
                conn.send_command_timing("screen-length disable")
            except Exception:
                pass

            # Liste de commandes candidates (par ordre de probabilité)
            commandes = [
                "display transceiver diagnosis interface",  # Comware/H3C/HP
                "display transceiver",                      # Huawei
                "show interfaces transceiver",              # Cisco/Aruba
            ]

            sortie, used_cmd = "", None
            for cmd in commandes:
                out = conn.send_command_timing(cmd)
                if out and "Invalid" not in out and "Unrecognized" not in out and out.strip():
                    sortie, used_cmd = out, cmd
                    break

            bloc_resultats.append(f"IP: {ip}")
            bloc_resultats.append(f"Commande utilisée: {used_cmd or 'aucune'}")

            # --- Cas particuliers ---
            if ip.endswith(".17"):
                # Exemple : AR651 → ports cuivre uniquement
                bloc_resultats.append(f"[{ip}] Aucun port SFP détecté (AR651 → ports cuivre)")
                stats_globales["equipements"] += 1
                resultats.append("\n".join(bloc_resultats))
                return

            if used_cmd == "show interfaces transceiver" and "Transceiver Technical Information:" in (sortie or ""):
                lignes = [l for l in sortie.splitlines() if l.strip()]
                if len(lignes) <= 2:  # tableau vide → aucun SFP
                    bloc_resultats.append(f"[{ip}] Aucun module SFP détecté")
                    stats_globales["equipements"] += 1
                    resultats.append("\n".join(bloc_resultats))
                    return

            # --- Parsing standard ---
            trs = extraire_transceivers(sortie or "")
            if not trs:
                bloc_resultats.append(f"[{ip}] Erreur : aucune donnée SFP trouvée")
                stats_globales["equipements"] += 1
                resultats.append("\n".join(bloc_resultats))
                return

            absents = sum(1 for t in trs if not t["present"])
            presents = sum(1 for t in trs if t["present"])
            total = len(trs)
            bloc_resultats.append(f"[{ip}] SFP présents: {presents} | absents: {absents} / {total}")

            # Mise à jour stats globales
            stats_globales["equipements"] += 1
            stats_globales["sfp_presents"] += presents
            stats_globales["sfp_absents"] += absents

            # Détails par port
            for t in trs:
                if not t["present"]:
                    bloc_resultats.append(f"[{ip}] Port {t['port']} : module ABSENT [True]")
                    continue

                if not t["mesures"]:
                    bloc_resultats.append(f"[{ip}] Port {t['port']} : Présent (pas de mesures) [True]")
                    continue

                for metric, val, vmin, vmax, ok in t["mesures"]:
                    if ok:
                        bloc_resultats.append(
                            f"[{ip}] Port {t['port']} {metric}: {val} (seuil {vmin}..{vmax}) [True]"
                        )
                    else:
                        alerte = (
                            f"[{ip}] Port {t['port']} {metric} hors plage: {val} (seuil {vmin}..{vmax}) [False]"
                        )
                        bloc_resultats.append(alerte)
                        alertes.append(alerte)
                        stats_globales["alertes"] += 1

    except Exception as e:
        bloc_resultats.append(f"[{ip}] Erreur : {str(e)}")
        stats_globales["equipements"] += 1

    # Ajout du bloc dans la liste globale
    resultats.append("\n".join(bloc_resultats) + "\n" + "-" * 60)


# ============================================================
# Main
# ------------------------------------------------------------
#   - Demande login/mot de passe
#   - Lit les IPs dans "equipements.csv"
#   - Lance un thread par IP
#   - Affiche les résultats + un résumé global
#   - Écrit les alertes si besoin
# ============================================================
def main():
    print(" Audit SFP / Transceivers : ")

    user = input("Nom d'utilisateur : ")
    mdp = getpass.getpass("Mot de passe : ")

    with open("equipements.csv") as f:
        ips = [r["ip"].strip() for r in csv.DictReader(f)]

    threads, resultats, alertes = [], [], []
    stats_globales = {"equipements": 0, "sfp_presents": 0, "sfp_absents": 0, "alertes": 0}

    for ip in ips:
        if not ip:
            continue
        t = threading.Thread(target=auditer, args=(ip, user, mdp, resultats, alertes, stats_globales))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # Affichage final
    print("\n Résultats :\n")
    for r in resultats:
        print(r)

    print("\n================== RÉSUMÉ GLOBAL ==================")
    print(f"Équipements analysés : {stats_globales['equipements']}")
    print(f"SFP présents        : {stats_globales['sfp_presents']}")
    print(f"SFP absents         : {stats_globales['sfp_absents']}")
    print(f"Alertes détectées   : {stats_globales['alertes']}")
    print("==================================================")

    if alertes:
        with open("sfp_audit_alertes.txt", "w") as f:
            for a in alertes:
                f.write(a + "\n")
        print("\nAlerte(s) enregistrée(s) dans sfp_audit_alertes.txt")


# ============================================================
if __name__ == "__main__":
    main()