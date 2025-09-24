# Documentation technique du projet Audit/Remediation réseau

## Philosophie du projet

Ce projet vise à fournir une solution **automatisée**, **modulaire** et **extensible** pour auditer et remédier les configurations réseau du parc LAN. 
Il permet de détecter les non-conformités, de générer des rapports détaillés et, à terme l'objectif, sera de pouvoir corriger automatiquement les problèmes identifiés.

### Principes clés :
- **Séparation des responsabilités** : Audit, remédiation et reporting sont découplés pour une meilleure lisibilité et maintenabilité.
- **Modularité** : Chaque règle d'audit et chaque remédiation est implémentée comme une classe indépendante.
- **Extensibilité** : Ajout facile de nouveaux vendors, règles ou remédiations sans impacter l'existant.
- **Transparence** : Génération de rapports CSV et HTML clairs, avec des logs détaillés.
- **Robustesse** : Gestion des erreurs et prise en charge des spécificités des différents OS/vendors.

---

## Structure du projet

```
audit_remediation_framework/
├── main.py                      # Point d'entrée principal du projet. Il orchestre l'exécution des audits en parallèle, collecte les résultats et génère des rapports CSV et HTML.
├── requirements.txt             # Liste des dépendances Python nécessaires (fichier à créer pour Gitlab)
├── README.md                    # [TODO] Guide d'utilisation
├── docs/
│   └── documentation.md         # Documentation technique (ce fichier)
├── config/
│   └── ips.txt                  # Liste des IPs à auditer
├── audit/                       # Contient les modules liés à l'audit
│   ├── connection.py            # Gère les connexions SSH aux équipements via Netmiko. (possible d'ajouter d'autres méthodes comme Paramiko)
│   ├── discovery.py             # Détection de plateforme + collecte d'infos (Détecte le type d'équipement et collecte des informations (modèle, firmware, etc.).)
│   ├── runner.py                # Orchestrateur qui exécute les règles d'audit sur chaque équipement.
│   └── rules/                   # Contient les règles d'audit
│       ├── base_rules.py        # Classe de base abstraite pour les règles
│       ├── sysname.py           # Règle : validation du nom d'hôte
│       └── tacacs.py            # Règle : vérification de la connectivité TACACS
│       └── snmp_v3_test.py      # Règle : vérification du fonctionnement d'un compte SNMPv3 
├── remediation/                 # [WIP] Modules de remédiation
│   ├── base_remediation.py      # [WIP] Classe de base pour les remédiations
│   ├── sysname.py               # [WIP] Remédiation : correction du nom d'hôte
│   └── tacacs.py                # [WIP] Remédiation : correction de la connectivité TACACS
├── report/
│   └── dashboard.py             # Génération de rapports HTML enrichis
├── results/                     # Rapports générés (CSV et HTML)
├── tests/                       # [TODO] Tests unitaires
```

---

## Fonctionnalités en place

### **Audit**
- **Audit parallèle** : Plusieurs équipements peuvent être audités simultanément grâce à un `ThreadPoolExecutor`.
- **Détection intelligente** : Identification automatique du type d'équipement via Netmiko et expressions régulières.
- **Audit multi-vendor** :
  - HP Comware, HP ProCurve
  - Huawei VRP, Aruba OS
  - 3Com
- **Règles d'audit disponibles** :
  - **SysnameRule** : Vérifie si le nom d'hôte respecte un format spécifique.
  - **TacacsRule** : Vérifie la connectivité SSH/TACACS.
  - **SNMPv3CheckRule** : Vérifie la configuration SNMPv3.
- **Rapports CSV** : Export des résultats d'audit avec les colonnes suivantes :
  - IP, hostname, modèle, firmware, durée, conformité des règles, détails.

### **Reporting**
- **Rapport HTML** : Génération d'un tableau interactif et de graphiques (camemberts) à partir des résultats CSV.
- **CLI indépendante** : Possibilité de regénérer un rapport HTML à partir d'un fichier CSV existant.

### **Remédiation (en cours de développement)**
- **SysnameRemediation** : Correction des noms d'hôtes non conformes.
- **TacacsRemediation** : Correction des problèmes de connectivité TACACS.
- **SNMPv3Remediation** : Correction du paramétrage SNMP

---

## Utilisation

### **Audit complet via CLI**
```bash
python3 main.py -u user -p password -i config/ips.txt -r sysname,tacacs
```

#### Options disponibles :
- `-u` : Nom d'utilisateur SSH.
- `-p` : Mot de passe SSH (sinon demandé).
- `-i` : Fichier contenant les IPs des équipements à auditer.
- `-r` : Liste des règles à appliquer (par défaut, toutes les règles).
- `-o` : Nom du fichier CSV de sortie (par défaut, timestamp).

#### Résultats générés :
- `results/audit_YYYYMMDD_HHMMSS.csv` : Rapport CSV détaillé.
- `results/audit_YYYYMMDD_HHMMSS.html` : Rapport HTML enrichi.

---

### **Re-générer un rapport HTML à partir d'un CSV**
```bash
python3 report/dashboard.py -f results/audit_20250502_153210.csv
```

#### Options disponibles :
- `-f` : Chemin du fichier CSV source.
- `-o` : Chemin du fichier HTML de sortie (par défaut, `results/rapport_audit_graphs.html`).

---

## Prochaines étapes

1. **Compléter les modules de remédiation :**
   - Implémenter la logique pour corriger les configurations non conformes (noms d'hôtes, connectivité TACACS, etc.).
2. **Ajouter des tests unitaires :**
   - Créer un dossier `tests/` avec des tests pour chaque module (connexion, discovery, règles, remédiation).
3. **Améliorer la gestion des erreurs et des logs:**
   - Ajouter des blocs `try/except` dans `discovery.py` et `connection.py` pour mieux gérer les erreurs de connexion et de commande.
   - Utiliser le module `logging`
4. **Refactoriser `main.py` :**
   - Déplacer la logique d'exécution des audits et de génération des rapports dans des fonctions ou modules dédiés.
5. **Compléter `requirements.txt` :**
   - Ajouter les dépendances nécessaires (`Netmiko`, `pandas`, `jinja2`, etc.).

---

## Contribution

### Ajouter une règle d'audit :
1. Créer une nouvelle classe dans `audit/rules/`.
2. Hériter de `BaseAuditRule`.
3. Implémenter les méthodes `name` et `run`.
4. Ajouter la règle dans `ALL_RULES` dans `runner.py`.

---

## Contact

- Auteur : Alexis HUYGHE
- Version : `v1.4`
- Date : 07 Mai 2025