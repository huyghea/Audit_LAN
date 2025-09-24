"""Chargement des fichiers de configuration .ini."""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Dict


def read_ini(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    if not path.exists():
        return parser
    parser.read(path, encoding="utf-8")
    return parser


def load_main_config(path: Path) -> Dict[str, str]:
    parser = read_ini(path)
    if parser.has_section("audit"):
        return {key: value for key, value in parser.items("audit")}
    return {}


def load_rule_config(rule_name: str, base_dir: Path) -> Dict[str, str]:
    file_path = base_dir / f"{rule_name}.ini"
    parser = read_ini(file_path)
    if parser.has_section(rule_name):
        return {key: value for key, value in parser.items(rule_name)}
    if parser.sections():
        first_section = parser.sections()[0]
        return {key: value for key, value in parser.items(first_section)}
    return {}
