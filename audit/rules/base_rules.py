#!/usr/bin/env python3
from abc import ABC, abstractmethod

class BaseAuditRule(ABC):
    """
    Classe de base pour une règle d'audit.

    Chaque règle doit définir :
      - name (str)
      - run(self, info: dict) -> dict

    Le résultat retourné doit être un dict :
      {"name": <rule_name>, "passed": <bool>, "details": <str>}
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self, info: dict) -> dict:
        pass
