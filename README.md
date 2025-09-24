# Orchestrateur d'audits réseau

## Exécution

```bash
python3 main.py -u <utilisateur> -p <mot_de_passe>
```

Options principales :

* `-c` : chemin vers le fichier `main.ini` (par défaut `config/main.ini`).
* `-i` : fichier contenant les adresses IP (sinon celui défini dans la configuration).
* `-r` : liste de règles à exécuter (séparées par des virgules). Sans valeur, toutes les règles actives dans la configuration sont lancées.
* `-w` : nombre de threads.

Les identifiants SNMP peuvent être fournis via la ligne de commande ou des variables d'environnement (`SNMP_USER`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY`, `SNMP_AUTH_PROTO`, `SNMP_PRIV_PROTO`).

Les rapports CSV et HTML sont générés dans le dossier `results/` (modifiable dans `main.ini`).

## Structure de configuration

Chaque script Python possède un fichier `.ini` dédié dont le nom est dérivé du nom du script (ex.: `main.py` → `config/main.ini`, `cpu_usage.py` → `config/cpu_usage.ini`).

* `config/main.ini` : paramètres globaux (journalisation, nombre de threads, règles actives...).
* `config/<nom_regle>.ini` : paramètres spécifiques à chaque règle (commandes CLI, seuils, etc.).

## Ajouter une nouvelle règle d'audit

1. Créer une classe héritant de `BaseAuditRule` dans `audit/rules/`.
2. Enregistrer la classe dans `audit/rules/__init__.py`.
3. Créer le fichier `config/<nom_de_la_règle>.ini` contenant les paramètres configurables.
4. (Optionnel) Ajouter des fonctions de parsing testables et les couvrir avec `tests/test_parsers.py`.
5. Lancer les tests `python -m unittest`.
6. Ajouter le nom de la règle à `active_rules` dans `config/main.ini` si elle doit être exécutée par défaut.

## Lancer les tests unitaires

```bash
python -m unittest discover -s tests
```

La règle SNMPv3 nécessite `pysnmp`. Si cette dépendance n'est pas installée, elle est automatiquement désactivée pendant les tests.
