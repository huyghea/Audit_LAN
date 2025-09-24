"""Orchestrateur des audits réseau."""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List

from audit.config_loader import load_main_config
from audit.runner import instantiate_rules, run_audit
from audit.rules import RULE_REGISTRY
from audit.utils import parse_rules_argument
from report.dashboard import generate_html_dashboard

DEFAULT_CONFIG = Path("config") / "main.ini"


def load_ips(path: Path) -> List[str]:
    try:
        with path.open(encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        logging.error("Fichier IP introuvable: %s", path)
        return []


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Orchestrateur d'audits réseau modulaire"
    )
    parser.add_argument(
        "-u",
        "--username",
        required=True,
        help="Nom d'utilisateur SSH",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Mot de passe SSH (sinon saisie interactive)",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Fichier de configuration .ini",
    )
    parser.add_argument(
        "-r",
        "--rules",
        nargs="+",
        help=(
            "Règles à exécuter (noms séparés par un espace ou une virgule; "
            "'all' pour tout exécuter)"
        ),
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Affiche les règles disponibles puis quitte",
    )
    parser.add_argument(
        "-i",
        "--ips",
        type=Path,
        help="Fichier contenant les IPs cibles",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Chemin du rapport CSV",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        help="Nombre de threads parallèles",
    )

    parser.add_argument("--snmp-user", default=os.environ.get("SNMP_USER"))
    parser.add_argument(
        "--snmp-auth-key",
        default=os.environ.get("SNMP_AUTH_KEY"),
    )
    parser.add_argument(
        "--snmp-priv-key",
        default=os.environ.get("SNMP_PRIV_KEY"),
    )
    parser.add_argument(
        "--snmp-auth-proto",
        default=os.environ.get("SNMP_AUTH_PROTO"),
    )
    parser.add_argument(
        "--snmp-priv-proto",
        default=os.environ.get("SNMP_PRIV_PROTO"),
    )

    args = parser.parse_args()

    if args.list_rules:
        for rule_name in sorted(RULE_REGISTRY):
            print(rule_name)
        return

    config = load_main_config(args.config)
    log_level = config.get("log_level", "INFO")
    configure_logging(log_level)

    workers = args.workers or int(config.get("workers", 50))
    ips_file = args.ips or Path(config.get("ips_file", "config/ips.txt"))
    output_path = args.output
    if output_path is None:
        default_dir = config.get("output_dir", "results")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(default_dir) / f"audit_{timestamp}.csv"

    if not args.password:
        args.password = getpass.getpass("Mot de passe SSH : ")

    ips = load_ips(ips_file)
    if not ips:
        logging.warning("Aucune IP à auditer - arrêt")
        return

    cli_rules = parse_rules_argument(args.rules)
    if cli_rules:
        if any(rule == "all" for rule in cli_rules):
            active_rules = list(RULE_REGISTRY.keys())
        else:
            active_rules = cli_rules
    else:
        config_rules = parse_rules_argument(config.get("active_rules"))
        active_rules = config_rules or list(RULE_REGISTRY.keys())

    unknown_rules = [rule for rule in active_rules if rule not in RULE_REGISTRY]
    if unknown_rules:
        raise ValueError(f"Règles inconnues demandées: {', '.join(unknown_rules)}")

    rule_instances = instantiate_rules(active_rules, Path("config"))

    snmp_creds = {}
    if any(rule.name == "snmp_v3_check" for rule in rule_instances):
        snmp_creds = {
            "snmp_user": args.snmp_user or config.get("snmp_user"),
            "snmp_auth_key": (
                args.snmp_auth_key or config.get("snmp_auth_key")
            ),
            "snmp_priv_key": (
                args.snmp_priv_key or config.get("snmp_priv_key")
            ),
            "snmp_auth_proto": (
                args.snmp_auth_proto
                or config.get("snmp_auth_proto", "SHA")
            ).upper(),
            "snmp_priv_proto": (
                args.snmp_priv_proto
                or config.get("snmp_priv_proto", "AES")
            ).upper(),
        }
        required_keys = {"snmp_user", "snmp_auth_key", "snmp_priv_key"}
        missing = [
            key
            for key, value in snmp_creds.items()
            if key in required_keys and not value
        ]
        if missing:
            logging.warning(
                "Identifiants SNMP incomplets : %s",
                ", ".join(missing),
            )

    logging.info(
        "Démarrage audit: %s règles | %s équipements | %s threads",
        ",".join(rule.name for rule in rule_instances),
        len(ips),
        workers,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["ip", "duration", "hostname", "model", "firmware"]
    for rule in rule_instances:
        fieldnames += [f"{rule.name}_compliant", f"{rule.name}_details"]

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                run_audit,
                ip,
                args.username,
                args.password,
                rule_instances,
                snmp_creds,
            ): ip
            for ip in ips
        }
        for idx, future in enumerate(as_completed(futures), start=1):
            ip_address = futures[future]
            try:
                row = future.result()
                rows.append(row)
                logging.info(
                    "[%s/%s] %s - %s",
                    idx,
                    len(ips),
                    ip_address,
                    row.get("hostname", "N/A"),
                )
            except Exception as exc:  # pragma: no cover - dépend runtime
                logging.exception(
                    "Erreur pendant le traitement de %s",
                    ip_address,
                )
                error_row = {
                    "ip": ip_address,
                    "duration": 0,
                    "hostname": "ERROR",
                    "model": str(exc),
                    "firmware": "",
                }
                for rule in rule_instances:
                    error_row[f"{rule.name}_compliant"] = False
                    error_row[f"{rule.name}_details"] = "Erreur d'exécution"
                rows.append(error_row)

    with output_path.open("w", newline="", encoding="utf-8") as csv_handle:
        writer = csv.DictWriter(csv_handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: str(value) for key, value in row.items()})

    logging.info("Rapport CSV: %s", output_path)
    html_output = output_path.with_suffix(".html")
    generate_html_dashboard(str(output_path), str(html_output))
    logging.info("Rapport HTML: %s", html_output)


if __name__ == "__main__":
    main()
