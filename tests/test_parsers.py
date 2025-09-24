"""Tests unitaires des fonctions de parsing."""

from __future__ import annotations

import unittest

from audit.parsers.hardware import (
    clean_cli_output,
    extract_model,
    extract_version_and_firmware,
)
from audit.rules.cpu_usage import parse_cpu_output
from audit.rules.fan_health import analyse_fans
from audit.rules.hardware_inventory import HardwareInventoryRule
from audit.rules.memory_usage import extract_usage_percent
from audit.rules.power_supply import analyse_power
from audit.rules.storage_capacity import extract_disk_usage, extract_firmwares
from audit.rules.temperature import parse_temperatures
from audit.rules.transceiver_diagnostics import parse_transceivers
from audit.rules.uptime import parse_uptime
from audit.utils import parse_rules_argument, resolve_disable_paging_commands


class ParserTests(unittest.TestCase):
    def test_hardware_cleaning(self) -> None:
        raw = "\x1b[31mSwitch\x1b[0m\r\nPress any key to continue...\n"
        cleaned = clean_cli_output(raw)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("Press any key", cleaned)

    def test_hardware_model_and_version(self) -> None:
        output = (
            "HPE 5130 EI Switch with 4 slots\n"
            "Comware Software, Version 7.1.059, Release 3307P06\n"
        )
        model = extract_model(output)
        version, firmware = extract_version_and_firmware(output)
        self.assertEqual(model, "5130 EI")
        self.assertEqual(version, "7.1.059")
        self.assertEqual(firmware, "7.1.059, Release 3307P06")

    def test_cpu_parse_generic(self) -> None:
        output = "Five seconds: 23% One minute: 12% Five minutes: 5%"
        values, labels = parse_cpu_output(output)
        self.assertEqual(values, [23.0, 12.0, 5.0])
        self.assertEqual(labels, ["5s", "1m", "5m"])

    def test_memory_percent(self) -> None:
        self.assertEqual(extract_usage_percent("Memory usage: 83%"), 83.0)
        self.assertIsNone(extract_usage_percent("No percent here"))

    def test_fan_analysis(self) -> None:
        ok, total = analyse_fans("Fan1 Normal\nFan2 Faulty")
        self.assertEqual((ok, total), (1, 2))

    def test_power_analysis(self) -> None:
        ok, fault, absent, total = analyse_power("Power 1 : OK\nPower 2 : Fault\nPower 3 : Absent")
        self.assertEqual((ok, fault, absent, total), (1, 1, 1, 3))

    def test_storage_parsers(self) -> None:
        disk_output = "524288 KB total (173956 KB free)"
        self.assertEqual(extract_disk_usage(disk_output), (524288, 173956))
        fw_output = "-rw-    174,624,256  some-image.bin"
        self.assertEqual(extract_firmwares(fw_output), [("some-image.bin", 174624256)])

    def test_temperature_table(self) -> None:
        output = "Temp: 35 C, Warning: 65 C, Alarm: 75 C"
        temps, lower, warn, alarm = parse_temperatures(output)
        self.assertEqual(temps[0], 35.0)
        self.assertEqual((lower, warn, alarm), (None, 65.0, 75.0))

    def test_transceiver_parse(self) -> None:
        output = (
            "GigabitEthernet1/0/1 transceiver diagnostic information:\n"
            "  Temperature : 35 Threshold : -5 to 85\n"
            "  Voltage : 3.3 Threshold : 3.0 to 3.6\n"
        )
        parsed = parse_transceivers(output)
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["present"])
        self.assertEqual(len(parsed[0]["measurements"]), 2)

    def test_uptime_parser(self) -> None:
        output = (
            "Uptime is 1 weeks, 2 days, 3 hours, 4 minutes\n"
            "Last reboot reason : power-off"
        )
        formatted, reason, seconds = parse_uptime(output)
        self.assertEqual(reason, "power-off")
        self.assertEqual(seconds, 1 * 7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60)
        self.assertIn("weeks", formatted)

    def test_parse_rules_argument(self) -> None:
        self.assertEqual(parse_rules_argument("sysname,tacacs"), ["sysname", "tacacs"])
        self.assertEqual(
            parse_rules_argument(["cpu_usage", "cpu_usage", "memory_usage"]),
            ["cpu_usage", "memory_usage"],
        )
        self.assertEqual(
            parse_rules_argument(["snmp_v3_check,memory_usage", "ALL"]),
            ["snmp_v3_check", "memory_usage", "all"],
        )
        self.assertEqual(parse_rules_argument(None), [])

    def test_resolve_disable_paging_commands(self) -> None:
        self.assertEqual(
            resolve_disable_paging_commands("huawei", None)[0],
            "screen-length disable",
        )
        defaults = resolve_disable_paging_commands("unknown", None)
        self.assertIn("no page", defaults)
        custom = resolve_disable_paging_commands("huawei", "undo page,no page")
        self.assertEqual(custom, ["undo page", "no page"])

    def test_hardware_inventory_cache(self) -> None:
        rule = HardwareInventoryRule(config={})
        cache = {
            "model": "N/A",
            "version": "N/A",
            "firmware": "N/A",
            "command": "display version",
            "raw_output": (
                "Aruba 2930F 24G 4SFP Switch with 4 slots\n"
                "Product Name : JL258A\n"
                "Software Version : WC.16.08.001\n"
            ),
        }
        result = rule.run({"hardware_inventory": cache})
        self.assertTrue(result["passed"])
        self.assertIn("2930F", result["details"])
        self.assertIn("via display version", result["details"])

if __name__ == "__main__":
    unittest.main()
