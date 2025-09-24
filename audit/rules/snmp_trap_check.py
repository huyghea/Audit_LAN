#!/usr/bin/env python3
from .base_rules import BaseAuditRule
import re

class SnmpTrapCheckRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "snmp_trap_check"

    def run(self, info: dict) -> dict:
        shell = info.get("shell")
        if not shell:
            return {"passed": False, "details": f"Shell SSH non fourni. Info: {info}"}

        try:
            success, output = self._execute_command(shell, "dis cur | inc snmp")
            if not success:
                return {"passed": False, "details": "Échec lors de l'exécution de la commande 'dis cur | inc snmp'."}

            if info.get("marque", "").lower() != "huawei":
                success, extra_output = self._execute_command(shell, "dis snmp-agent trap-list")
                if not success:
                    return {"passed": False, "details": "Échec lors de l'exécution de la commande 'dis snmp-agent trap-list'."}
                output += "\n" + extra_output

            passed, details = self._analyze_snmp_traps(output, info.get("marque", ""), info.get("type", ""), info.get("comware_version", ""))
            return {"passed": passed, "details": details}

        except Exception as e:
            return {"passed": False, "details": f"Erreur inattendue : {str(e)}"}

    def _execute_command(self, shell, command):
        """
        Exécute une commande sur le shell SSH et retourne le résultat, en gérant la pagination.
        """
        try:
            # Envoi de la commande initiale
            output = shell.send_command_timing(command)
            
            # Gestion de la pagination
            while "---- More ----" in output:
                output += shell.send_command_timing(" ")  # Envoi d'un espace pour continuer la sortie
            
            return True, output
        except Exception as e:
            return False, str(e)

    def _analyze_snmp_traps(self, output, type_equipement, marque, comware_version):
        """
        Analyse la configuration SNMP pour vérifier la conformité des traps.
        """
        lines = output.split("\n")
        lines = [line.strip() for line in lines if line.strip()]  # Supprime les lignes vides

        if len(lines) < 3:
            return False, "Configuration SNMP incomplète ou équipement trop lent à répondre."

        # Initialisation des variables
        trap_enable = False
        target_host_2941 = False
        target_host_30166 = False
        issues = []

        # Analyse des lignes de configuration
        for line in lines:
            if re.search("---- More ----", line):
                return False, "Pagination détectée dans la sortie, commande non terminée."

            if not trap_enable and re.search(r"snmp-agent trap enable", line):
                trap_enable = True

            if re.search(r"snmp-agent target-host.*10\.105\.29\.41", line):
                target_host_2941 = True

            if re.search(r"snmp-agent target-host.*10\.105\.30\.166", line):
                target_host_30166 = True

            # Vérifications spécifiques à Huawei
            if marque == "huawei":
                if type_equipement == "lmz" and re.search(r"undo snmp-agent trap enable", line):
                    issues.append(f"Ligne non conforme détectée : {line}")

        # Vérifications finales
        if not trap_enable:
            issues.append("Trap SNMP non activé (snmp-agent trap enable manquant).")
        if not target_host_2941:
            issues.append("Trap vers 10.105.29.41 manquant.")
        if not target_host_30166:
            issues.append("Trap vers 10.105.30.166 manquant.")

        if issues:
            return False, "; ".join(issues)
        return True, "Configuration SNMP conforme."