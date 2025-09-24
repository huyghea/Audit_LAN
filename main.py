#!/usr/bin/env python3
# main.py

import os
import csv
import getpass
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from report.dashboard import generate_html_dashboard
from audit.runner import run_audit, ALL_RULES

def load_ips(path="config/ips.txt"):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"Error: IP file not found at {path}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Parallel audit (selective rules)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=False, help="SSH password (prompt if not provided)")
    parser.add_argument("-i", "--ips", default="config/ips.txt", help="IPs file (default: config/ips.txt)")
    parser.add_argument("-r", "--rules", default=None,
                        help=f"Comma-separated list of rules (choices: {','.join(ALL_RULES.keys())}). All if absent.")
    parser.add_argument("-o", "--output", default=None, help="CSV output file (default: results/audit_YYYYMMDD_HHMMSS.csv)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of parallel workers (default: 100)")

    parser.add_argument("--snmp-user", default=os.environ.get("SNMP_USER"), help="SNMPv3 username (or ENV: SNMP_USER)")
    parser.add_argument("--snmp-auth-key", default=os.environ.get("SNMP_AUTH_KEY"), help="SNMPv3 auth key (or ENV: SNMP_AUTH_KEY)")
    parser.add_argument("--snmp-priv-key", default=os.environ.get("SNMP_PRIV_KEY"), help="SNMPv3 priv key (or ENV: SNMP_PRIV_KEY)")
    parser.add_argument("--snmp-auth-proto", default=os.environ.get("SNMP_AUTH_PROTO", "SHA"), help="SNMPv3 auth protocol (default: SHA, or ENV: SNMP_AUTH_PROTO)")
    parser.add_argument("--snmp-priv-proto", default=os.environ.get("SNMP_PRIV_PROTO", "AES"), help="SNMPv3 priv protocol (default: AES, or ENV: SNMP_PRIV_PROTO)")

    args = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass("SSH Password: ")

    ips = load_ips(args.ips)
    if not ips:
        print("No IPs to audit. Exiting.")
        return

    snmp_creds = {}
    snmp_rule_active = False
    if args.rules:
        if "snmp_v3_check" in args.rules.split(','):
            snmp_rule_active = True
    elif ALL_RULES.get("snmp_v3_check"):
        snmp_rule_active = True

    if snmp_rule_active:
        print("\n--- SNMPv3 Configuration for 'snmp_v3_check' rule ---")
        prompt_snmp_user = args.snmp_user
        prompt_snmp_auth_key = args.snmp_auth_key
        prompt_snmp_priv_key = args.snmp_priv_key

        if not prompt_snmp_user:
            prompt_snmp_user = input("Enter SNMPv3 Username: ")
        if not prompt_snmp_auth_key:
            prompt_snmp_auth_key = getpass.getpass("Enter SNMPv3 Auth Key: ")
        if not prompt_snmp_priv_key:
            prompt_snmp_priv_key = getpass.getpass("Enter SNMPv3 Priv Key: ")

        if all([prompt_snmp_user, prompt_snmp_auth_key, prompt_snmp_priv_key]):
            snmp_creds = {
                "snmp_user": prompt_snmp_user,
                "snmp_auth_key": prompt_snmp_auth_key,
                "snmp_priv_key": prompt_snmp_priv_key,
                "snmp_auth_proto": args.snmp_auth_proto.upper(),
                "snmp_priv_proto": args.snmp_priv_proto.upper()
            }
            print(f"Using SNMP Auth Protocol: {snmp_creds['snmp_auth_proto']}")
            print(f"Using SNMP Priv Protocol: {snmp_creds['snmp_priv_proto']}")
        else:
            print("Warning: Incomplete SNMPv3 credentials provided. 'snmp_v3_check' rule will likely fail or report as non-compliant.")
            snmp_creds = {}

    rules_to_run_instances = []
    if args.rules:
        requested_rule_names = [r.strip() for r in args.rules.split(",")]
        unknown = set(requested_rule_names) - set(ALL_RULES.keys())
        if unknown:
            parser.error(f"Unknown rules: {','.join(unknown)}")
        rules_to_run_instances = [ALL_RULES[name] for name in requested_rule_names]
    else:
        rules_to_run_instances = list(ALL_RULES.values())

    fieldnames = ["ip", "duration", "hostname", "model", "firmware"]
    for rule_obj in rules_to_run_instances:
        fieldnames += [f"{rule_obj.name}_compliant", f"{rule_obj.name}_details"]

    if args.output:
        csv_file = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = f"results/audit_{ts}.csv"
    output_dir = os.path.dirname(csv_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"\n=== Parallel Audit (rules: {'all' if not args.rules else args.rules}, {args.workers} workers) ===\n")
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(run_audit, ip, args.username, args.password, rules_to_run_instances, snmp_creds): ip
            for ip in ips
        }
        for i, f in enumerate(as_completed(futures)):
            ip_processed = futures[f]
            try:
                result_row = f.result()
                rows.append(result_row)
                print(f"Processed ({i+1}/{len(ips)}): {ip_processed} - Host: {result_row.get('hostname', 'N/A')}")
            except Exception as exc:
                print(f"ERROR during processing of {ip_processed}: {exc}")
                error_row = {"ip": ip_processed, "duration": 0, "hostname": "ERROR", "model": str(exc), "firmware": ""}
                for rule_obj in rules_to_run_instances:
                    error_row[f"{rule_obj.name}_compliant"] = False
                    error_row[f"{rule_obj.name}_details"] = "IP Processing Error"
                rows.append(error_row)

    try:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in rows:
                writer.writerow({key: str(value) for key, value in row.items()})
        print(f"\n📄 CSV report written to {csv_file}")

        html_output = csv_file.replace(".csv", ".html")
        generate_html_dashboard(csv_file, html_output)
        print(f"📄 HTML report written to {html_output}")

    except IOError as e:
        print(f"Error writing CSV/HTML file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during report generation: {e}")

if __name__ == "__main__":
    main()