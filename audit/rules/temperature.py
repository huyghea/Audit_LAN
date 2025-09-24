"""Contrôle des températures d'équipement."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .base_rules import BaseAuditRule
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)


def _is_separator(line: str) -> bool:
    return bool(re.match(r"^\s*-{3,}\s*$", line))


def _is_prompt(line: str) -> bool:
    return bool(re.match(r"^<.*?>$", line.strip()))


def _compute_columns(header_line: str) -> List[Tuple[str, int, int]]:
    columns: List[Tuple[str, int, int]] = []
    length = len(header_line)
    idx = 0
    start: Optional[int] = None

    while idx < length:
        if start is None and header_line[idx] != " ":
            start = idx
        elif start is not None and header_line[idx] == " ":
            end = idx
            while idx < length and header_line[idx] == " ":
                idx += 1
            name = header_line[start:end].strip().lower()
            if name:
                columns.append((name, start, end))
            start = None
            continue
        idx += 1

    if start is not None:
        name = header_line[start:].strip().lower()
        if name:
            columns.append((name, start, length))

    return columns


def _slice(line: str, start: int, end: int) -> str:
    if start >= len(line):
        return ""
    return line[start:min(end, len(line))].strip()


def _find_column(
    columns: List[Tuple[str, int, int]],
    keys: List[str],
) -> Optional[Tuple[int, int]]:
    for key in keys:
        for name, start, end in columns:
            if key in name:
                return start, end
    return None


def _parse_table(
    lines: List[str],
) -> Tuple[List[float], Optional[float], Optional[float], Optional[float]]:
    header_index = None
    for idx, line in enumerate(lines):
        low = line.lower()
        if "information" in low:
            continue
        if re.search(r"\btemperature\b", low) or "temp(c)" in low:
            if len(re.split(r"\s{2,}", line.strip())) >= 2:
                header_index = idx
                break

    if header_index is None:
        return [], None, None, None

    columns = _compute_columns(lines[header_index])
    if not columns:
        return [], None, None, None

    temp_span = _find_column(columns, ["temperature", "temp", "temp(c)"])
    warn_span = _find_column(columns, ["warning", "upper", "warninglimit"])
    alarm_span = _find_column(columns, ["alarm", "shutdown"])
    lower_span = _find_column(columns, ["lower", "lowerlimit"])

    if temp_span is None:
        return [], None, None, None

    temps: List[float] = []
    warns: List[float] = []
    alarms: List[float] = []
    lowers: List[float] = []

    for line in lines[header_index + 1 :]:
        stripped = line.strip()
        if not stripped or _is_separator(stripped) or _is_prompt(stripped):
            continue

        match = re.search(r"-?\d+(?:\.\d+)?", _slice(line, *temp_span))
        if match:
            temps.append(float(match.group(0)))

        for span, container in (
            (warn_span, warns),
            (alarm_span, alarms),
            (lower_span, lowers),
        ):
            if span:
                value_match = re.search(
                    r"-?\d+(?:\.\d+)?",
                    _slice(line, *span),
                )
                if value_match:
                    container.append(float(value_match.group(0)))

    if not temps:
        return [], None, None, None

    lower = min(lowers) if lowers else None
    warn = min(warns) if warns else None
    alarm = min(alarms) if alarms else None
    return temps, lower, warn, alarm


def _parse_text(
    output: str,
) -> Tuple[List[float], Optional[float], Optional[float], Optional[float]]:
    temps = [
        float(match.group(1))
        for match in re.finditer(
            r"(-?\d+(?:\.\d+)?)\s*°?\s*C",
            output,
            re.IGNORECASE,
        )
    ]

    def grab(tag: str) -> Optional[float]:
        pattern = (
            fr"{tag}[^0-9-]*(-?\d+(?:\.\d+)?)\s*°?\s*C"
        )
        match = re.search(pattern, output, re.IGNORECASE)
        return float(match.group(1)) if match else None

    warn = grab("warning") or grab("upper")
    alarm = grab("alarm")
    lower = grab("lower")
    return temps, lower, warn, alarm


def parse_temperatures(
    output: str,
) -> Tuple[List[float], Optional[float], Optional[float], Optional[float]]:
    lines = output.splitlines()
    temps, lower, warn, alarm = _parse_table(lines)
    if temps or any(v is not None for v in (lower, warn, alarm)):
        return temps, lower, warn, alarm
    return _parse_text(output)


class TemperatureRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "temperature"

    def run(self, info: dict) -> dict:
        connection = info.get("connection") or info.get("shell")
        if connection is None:
            return {
                "name": self.name,
                "passed": False,
                "details": "Connexion SSH indisponible",
            }

        disable_commands = resolve_disable_paging_commands(
            info.get("device_type"),
            self.config.get(
                "disable_paging",
                "screen-length disable,screen-length 0 temporary",
            ),
        )
        disable_paging(connection, disable_commands)

        commands = normalize_list(
            self.config.get(
                "commands",
                "display temperature all,display env,display environment",
            )
        )

        for command in commands:
            output = run_command_with_paging(connection, command)
            if not output.strip():
                continue

            temps, lower, warn, alarm = parse_temperatures(output)
            if not temps:
                continue

            thresholds = [value for value in (warn, alarm) if value is not None]
            if thresholds:
                threshold = min(thresholds)
            else:
                threshold = float(self.config.get("default_threshold", 60))
            max_temp = max(temps)
            passed = max_temp <= threshold

            def _fmt(value: Optional[float]) -> str:
                return f"{value:.1f}°C" if value is not None else "NA"

            details = (
                f"Température max {max_temp:.1f}°C (seuil {threshold:.1f}°C) via {command}"
                f" | Lower:{_fmt(lower)} Warning:{_fmt(warn)} Alarm:{_fmt(alarm)}"
            )

            if not passed:
                details += " - dépassement de seuil"

            return {
                "name": self.name,
                "passed": passed,
                "details": details,
            }

        return {
            "name": self.name,
            "passed": False,
            "details": "Aucune mesure de température disponible",
        }
