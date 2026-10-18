"""Validate forwarding scope and recovery without router or network access."""

from __future__ import annotations

import copy
from pathlib import Path
import unittest

from fake_router import read_json, write_json
import test_camera_aliases as aliases


OWNER = "AnyToOmada camera forwarding v1"
INSTALLER = Path(__file__).resolve().parents[1] / "camera-forwarding.sh"


def expected_rules() -> dict[str, dict[str, str]]:
    """Independent operator-approved tuple matrix, including dual-lens sources."""
    physical = ("10.30.30.2", "10.30.30.4", "10.30.30.10", "10.30.30.10", "10.30.30.13", "10.30.30.13")
    result = {}
    for index, camera in enumerate(physical):
        suffix = 210 + index
        rows = (
            ("nvr_https", "10.20.0.150", 443, "192.168.100.100", 18443 + index),
            ("nvr_rtsp", "10.20.0.150", 554, "192.168.100.100", 18554 + index),
            ("nas_rtsp", "192.168.100.100", 554, camera, 554),
            ("nas_native", "192.168.100.100", 37777, camera, 37777),
        )
        for role, source, port, destination, backend in rows:
            name = f"ato_fwd_{suffix}_{role}"
            result[name] = {
                "__type__": "redirect", "ato_owner": OWNER,
                "name": f"AnyToOmada {name}", "family": "ipv4",
                "src": "wan", "src_ip": source, "src_dip": f"10.30.30.{suffix}",
                "src_dport": str(port), "dest": "wan", "dest_ip": destination,
                "dest_port": str(backend), "proto": "tcp", "target": "DNAT", "reflection": "0",
            }
    return result


class CameraForwardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = aliases.CameraAliasesTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.seed_installed_aliases()
        self.root = self.fixture.root
        source = INSTALLER.read_text(encoding="utf-8")
        for prefix in ("/etc/", "/var/lock/", "/tmp/", "/overlay"):
            source = source.replace(prefix, f"{self.root}{prefix}")
        self.fixture.script = self.root / "camera-forwarding.sh"
        self.fixture.script.write_text(source, encoding="utf-8")
        self.firewall = read_json(self.root / "etc/config/firewall")
        self.firewall["wan_zone"] = {
            "__type__": "zone", "name": "wan", "masq": "1", "input": "DROP",
        }
        self.set_firewall(self.firewall)
        self.before_network = (self.root / "etc/config/network").read_bytes()
        self.before_addresses = self.fixture.state()["addresses"]

    def set_firewall(self, config: dict) -> None:
        write_json(self.root / "etc/config/firewall", config)
        self.fixture.update_state(active_firewall=config)

    def assert_foundation_preserved(self) -> None:
        self.assertEqual((self.root / "etc/config/network").read_bytes(), self.before_network)
        self.assertEqual(self.fixture.state()["addresses"], self.before_addresses)
        current = read_json(self.root / "etc/config/firewall")
        for name, section in self.firewall.items():
            self.assertEqual(current[name], section)
        events = self.fixture.state()["events"]
        self.assertFalse(any(event["command"] in {"ifup", "ifdown"} for event in events))
        self.assertFalse(any(event["command"] == "ubus" and event["args"] == ["call", "network", "reload"] for event in events))
        self.assertFalse(any(event["command"] == "nft" and event["args"] == ["-f", "-"] for event in events))

    def test_check_does_not_change_configuration_or_runtime(self) -> None:
        result = self.fixture.run_installer("check")
        self.assertIn("Owned redirects: 0/24", result.stdout)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)
        self.assert_foundation_preserved()

    def test_missing_or_inactive_alias_and_guard_are_refused(self) -> None:
        network = read_json(self.root / "etc/config/network")
        del network["ato_cam_215"]
        write_json(self.root / "etc/config/network", network)
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("Required owned alias", result.stderr)
        (self.root / "etc/config/network").write_bytes(self.before_network)
        self.fixture.update_state(addresses={key: value for key, value in self.before_addresses.items() if key != "10.30.30.215/32"})
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("not active", result.stderr)
        self.fixture.update_state(addresses=self.before_addresses, omit_guard=True)
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("Active INPUT guard", result.stderr)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)

    def test_pending_edits_are_preserved_and_refused(self) -> None:
        for package in ("network", "firewall", "wireless"):
            with self.subTest(package=package):
                pending = self.root / f"pending-{package}.json"
                pending.write_text('{"unrelated": "pending"}', encoding="utf-8")
                result = self.fixture.run_installer("apply", succeeds=False)
                self.assertIn(f"pending {package}", result.stderr)
                self.assertTrue(pending.exists())
                pending.unlink()
        self.assert_foundation_preserved()

    def test_unknown_owned_names_and_owners_are_refused(self) -> None:
        for name in ("ato_fwd_210_nvr_https", "ato_fwd_unrecognized"):
            with self.subTest(name=name):
                config = copy.deepcopy(self.firewall)
                config[name] = {"__type__": "redirect", "name": "Another owner"}
                self.set_firewall(config)
                before = (self.root / "etc/config/firewall").read_bytes()
                self.fixture.run_installer("apply", succeeds=False)
                self.assertEqual((self.root / "etc/config/firewall").read_bytes(), before)

    def test_unowned_vip_or_broad_redirects_are_refused(self) -> None:
        references = (
            {"src_dip": "10.30.30.210"},
            {"src_dip": "10.30.30.0/24"},
            {"src_dip": ""},
            {"src_dip": "10.20.0.9", "dest_ip": "10.30.30.215"},
        )
        for reference in references:
            with self.subTest(reference=reference):
                config = copy.deepcopy(self.firewall)
                config["other_forward"] = {"__type__": "redirect", **reference}
                self.set_firewall(config)
                result = self.fixture.run_installer("apply", succeeds=False)
                self.assertIn("Unowned redirect", result.stderr)
                self.assertEqual(read_json(self.root / "etc/config/firewall"), config)

    def test_restricted_wan_masquerade_is_refused(self) -> None:
        config = copy.deepcopy(self.firewall)
        config["wan_zone"]["masq_src"] = "192.168.8.0/24"
        self.set_firewall(config)
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("unrestricted IPv4 masquerade", result.stderr)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), config)

    def test_apply_installs_only_exact_source_restricted_tcp_matrix(self) -> None:
        self.fixture.run_installer("apply")
        current = read_json(self.root / "etc/config/firewall")
        rules = {name: value for name, value in current.items() if name.startswith("ato_fwd_")}
        self.assertEqual(rules, expected_rules())
        self.assertEqual(len(rules), 24)
        self.assertEqual(set(current) - set(self.firewall), set(rules))
        self.assert_foundation_preserved()

    def test_remove_keeps_aliases_guard_tv_and_masquerade(self) -> None:
        self.set_firewall({**self.firewall, **expected_rules()})
        self.fixture.run_installer("remove")
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)
        self.assert_foundation_preserved()

    def test_failed_reload_restores_previous_firewall(self) -> None:
        before = (self.root / "etc/config/firewall").read_bytes()
        self.fixture.update_state(failures=[{"command": "firewall", "contains": "reload", "remaining": 1}])
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("previous firewall restored", result.stderr)
        self.assertEqual((self.root / "etc/config/firewall").read_bytes(), before)
        self.assertEqual(self.fixture.state()["active_firewall"], self.firewall)
        self.assert_foundation_preserved()

    def test_broadened_rendered_rule_is_rejected_before_commit(self) -> None:
        self.fixture.update_state(broaden_forwarding=True)
        result = self.fixture.run_installer("apply", succeeds=False)
        self.assertIn("Rendered DNAT rules", result.stderr)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)
        self.assertFalse(any(event["command"] == "firewall" for event in self.fixture.state()["events"]))
        self.assert_foundation_preserved()


if __name__ == "__main__":
    unittest.main()
