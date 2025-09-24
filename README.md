# Orchestrateur d'audits réseau

## Exécution

```bash
python3 main.py -u <utilisateur> -p <mot_de_passe>
```

Options principales :

* `-c` : chemin vers le fichier `main.ini` (par défaut `config/main.ini`).
* `-i` : fichier contenant les adresses IP (sinon celui défini dans la configuration).
* `-r/--rules` : noms des règles à exécuter (séparés par un espace ou une virgule). Utiliser `all` pour forcer l'exécution de l'ensemble des contrôles.
* `--list-rules` : affiche la liste des règles disponibles puis quitte (utile pour paramétrer un job Rundeck).
* `-w` : nombre de threads.

Les identifiants SNMP peuvent être fournis via la ligne de commande ou des variables d'environnement (`SNMP_USER`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY`, `SNMP_AUTH_PROTO`, `SNMP_PRIV_PROTO`).

Les rapports CSV et HTML sont générés dans le dossier `results/` (modifiable dans `main.ini`).

### Intégration dans Rundeck

1. Créer un job en mode `Command` et pointer vers `python3 main.py`.
2. Déclarer des options Rundeck (ex. `username`, `password`, `rules`, `config`) et mappez-les aux arguments CLI, par exemple :

   ```bash
   python3 main.py -u @option.username@ -p @option.password@ -c @option.config@ --rules @option.rules@
   ```

   * Pour lancer l'intégralité des contrôles, passez `rules=all` ou laissez le champ vide pour s'appuyer sur `active_rules` dans `main.ini`.
   * Pour un sous-ensemble, fournissez une liste séparée par des espaces : `rules="cpu_usage memory_usage"`.
3. Les secrets (mot de passe SSH, clés SNMP) peuvent être injectés via les `Secure Options` Rundeck ou des variables d'environnement.
4. Activez l'option `--list-rules` dans un job de diagnostic afin de synchroniser automatiquement les listes déroulantes Rundeck.

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
