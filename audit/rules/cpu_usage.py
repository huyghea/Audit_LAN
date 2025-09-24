"""Vérification de la charge CPU."""

from __future__ import annotations

import re
from statistics import mean
from typing import List, Tuple

from .base_rules import BaseAuditRule
from ..utils import (
    disable_paging,
    normalize_list,
    resolve_disable_paging_commands,
    run_command_with_paging,
)


def parse_cpu_output(output: str) -> Tuple[List[float], List[str]]:
    """Extrait les valeurs CPU et leurs labels depuis une sortie CLI."""

    values: List[float] = []
    labels: List[str] = []

    control = re.search(
        r"Control\s+Plane(.*?)(?=Data\s+Plane|$)",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if control:
        block = control.group(1)
        now_match = re.search(
            r"CPU\s*Usage:\s*([\d.]+)\s*%",
            block,
            re.IGNORECASE,
        )
        hist_match = re.search(
            (
                r"ten\s*seconds:\s*([\d.]+)%.*?"
                r"one\s*minute:\s*([\d.]+)%.*?"
                r"five\s*minutes:\s*([\d.]+)%"
            ),
            block,
            re.IGNORECASE | re.DOTALL,
        )
        if now_match:
            values.append(float(now_match.group(1)))
            labels.append("Now")
        if hist_match:
            values.extend(
                [float(hist_match.group(i)) for i in range(1, 4)]
            )
            labels.extend(["10s", "1m", "5m"])
        if values:
            return values, labels

    generic = re.search(
        (
            r"(\d+(?:\.\d+)?)%\s*in\s*last\s*5\s*seconds.*?"
            r"(\d+(?:\.\d+)?)%\s*in\s*last\s*1\s*minute.*?"
            r"(\d+(?:\.\d+)?)%\s*in\s*last\s*5\s*minutes"
        ),
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if generic:
        return [float(generic.group(i)) for i in range(1, 4)], ["5s", "1m", "5m"]

    textual = re.search(
        (
            r"Five\s*seconds:\s*(\d+(?:\.\d+)?)%.*?"
            r"One\s*minute:\s*(\d+(?:\.\d+)?)%.*?"
            r"Five\s*minutes:\s*(\d+(?:\.\d+)?)%"
        ),
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if textual:
        return [float(textual.group(i)) for i in range(1, 4)], ["5s", "1m", "5m"]

    idle_match = re.search(
        r"idle[^0-9]*?(\d+(?:\.\d+)?)\s*%",
        output,
        re.IGNORECASE,
    )
    if idle_match:
        load = 100.0 - float(idle_match.group(1))
        return [load], ["Now"]

    return [], []


class CpuUsageRule(BaseAuditRule):
    @property
    def name(self) -> str:
        return "cpu_usage"

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
                "screen-length disable,screen-length 0 temporary,no page,"
                "terminal length 0",
            ),
        )
        disable_paging(connection, disable_commands)

        commands = normalize_list(
            self.config.get(
                "commands",
                "display cpu-usage,display cpu,show cpu,"
                "show processes cpu,show processes cpu history",
            )
        )

        used_cmd: str | None = None
        output = ""
        for command in commands:
            output = run_command_with_paging(connection, command)
            values, labels = parse_cpu_output(output)
            if values:
                used_cmd = command
                break
        else:
            values, labels = [], []

        if not values:
            return {
                "name": self.name,
                "passed": False,
                "details": "Aucune métrique CPU détectée",
            }

        average = mean(values)
        peak = max(values)

        average_threshold = float(self.config.get("average_threshold", 80))
        peak_threshold = float(self.config.get("peak_threshold", 90))

        passed = average <= average_threshold and peak <= peak_threshold

        metrics = ", ".join(
            f"{label}:{value:.1f}%"
            for label, value in zip(labels, values)
        )
        details = (
            f"CPU OK ({metrics}) - moyenne {average:.1f}% / pic {peak:.1f}%"
            if passed
            else (
                f"CPU élevée ({metrics}) - seuils moy "
                f"{average_threshold:.1f}% / pic {peak_threshold:.1f}%"
            )
        )

        if used_cmd:
            details += f" via {used_cmd}"

        return {
            "name": self.name,
            "passed": passed,
            "details": details,
        }
