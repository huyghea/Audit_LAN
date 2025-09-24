"""Bases communes aux règles d'audit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseAuditRule(ABC):
    """Classe de base pour une règle d'audit configurable."""

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config: Dict[str, Any] = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Nom unique de la règle (utilisé pour l'activation)."""

    @abstractmethod
    def run(self, info: dict) -> dict:
        """Exécute la règle et retourne un dictionnaire de résultat."""
