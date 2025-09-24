"""Parsers partagés entre modules d'audit."""

from .hardware import clean_cli_output, extract_model, extract_version_and_firmware

__all__ = [
    "clean_cli_output",
    "extract_model",
    "extract_version_and_firmware",
]
