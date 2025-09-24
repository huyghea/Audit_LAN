#!/usr/bin/env python3
from .base_rules import BaseAuditRule
import re

class SysnameRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "sysname"

    def run(self, info: dict) -> dict:
        hostname = str(info.get("hostname", "")).upper()  # Assurez-vous que hostname est une chaîne
        # Vérification des règles
        passed = (
            hostname.startswith("NETW") or
            hostname.startswith("LMZFR") or
            hostname.startswith("CLM-") or
            bool(re.match(r"^R\d{2}[A-Z0-9\-]*$", hostname))  # Convertir le résultat en booléen
        )
        details = (
            f"Hostname '{str(info.get('hostname'))}' is compliant"
            if passed else
            f"Hostname '{str(info.get('hostname'))}' is not compliant"
        )
        return {"name": self.name, "passed": passed, "details": details}
