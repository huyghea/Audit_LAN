#!/usr/bin/env python3
from .base_rules import BaseAuditRule

class TacacsRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "tacacs"

    def run(self, info: dict) -> dict:
        conn = info.get("connection")
        passed = conn is not None
        details = (
            "SSH/TACACS connectivity OK"
            if passed else
            "SSH/TACACS connectivity FAILED"
        )
        return {"name": self.name, "passed": passed, "details": details}
