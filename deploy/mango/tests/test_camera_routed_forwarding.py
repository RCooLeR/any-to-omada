"""Verify routed VIP transactions and preservation without real networking."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from fake_router import read_json, write_json
import test_camera_aliases as aliases
from test_camera_forwarding import expected_rules

DIRECTORY = Path(__file__).resolve().parent
INSTALLER = DIRECTORY.parent / "camera-routed-forwarding.sh"
TABLE = "ato_routed_camera"
OWNER = "AnyToOmada routed camera forwarding v1"


class RoutedForwardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = aliases.CameraAliasesTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        (self.root / "var/run").mkdir()
        source = INSTALLER.read_text()
        for prefix in ("/etc/", "/var/lock/", "/var/run/", "/tmp/", "/overlay"):
            source = source.replace(prefix, f"{self.root}{prefix}")
        self.fixture.script = self.root / "camera-routed-forwarding.sh"
        self.fixture.script.write_text(source)
        fake = (DIRECTORY / "fake_routed_router.py").read_text()
        fake = fake.replace("from fake_router import Router", f"sys.path.insert(0, {str(DIRECTORY)!r})\nfrom fake_router import Router")
        for target in (self.root / "bin").iterdir():
            target.write_text(fake)
        self.firewall = read_json(self.root / "etc/config/firewall")
        self.firewall["wan_zone"] = {"__type__": "zone", "name": "wan", "masq": "1", "input": "DROP"}
        write_json(self.root / "etc/config/firewall", self.firewall)
        self.fixture.update_state(active_firewall=self.firewall)
        self.network = (self.root / "etc/config/network").read_bytes()
        self.addresses = copy.deepcopy(self.fixture.state()["addresses"])

    def run_script(self, action: str, *, succeeds: bool = True):
        return self.fixture.run_installer(action, succeeds=succeeds)

    def installed(self) -> dict:
        return read_json(self.root / "etc/config/firewall")

    def assert_preserved(self) -> None:
        self.assertEqual((self.root / "etc/config/network").read_bytes(), self.network)
        state = self.fixture.state()
        self.assertEqual(state["addresses"], self.addresses)
        for name, row in self.firewall.items():
            self.assertEqual(self.installed()[name], row)
        self.assertFalse(any(event["command"] in {"ifup", "ifdown", "firewall"} for event in state["events"]))
        self.assertFalse(any("flush" in event["args"] or "reload" in event["args"] for event in state["events"]))

    def test_check_only_checks_and_leaves_runtime_unchanged(self):
        self.run_script("check")
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})
        self.assert_preserved()

    def test_apply_exact_matrix_and_guards_and_rerun(self):
        self.run_script("apply")
        expected = {}
        for name, row in expected_rules().items():
            name = name.replace("ato_fwd_", "ato_rte_")
            expected[name] = {**row, "ato_owner": OWNER, "name": f"AnyToOmada routed {name}"}
        actual = {key: row for key, row in self.installed().items() if row["__type__"] == "redirect" and key.startswith("ato_rte_")}
        self.assertEqual(actual, expected)
        for chain in ("input", "forward"):
            guard = self.installed()[f"ato_rte_{chain}"]
            self.assertEqual(guard["dest_ip"], [f"10.30.30.{last}" for last in range(210, 216)])
            self.assertEqual(guard["target"], "DROP")
        table = self.fixture.state()["tables"][TABLE]
        self.assertEqual(table.count("dnat ip to "), 24)
        self.assertEqual(table.count("counter drop"), 2)
        self.run_script("apply")
        self.assertEqual(self.fixture.state()["tables"][TABLE], table)
        self.assert_preserved()

    def test_generated_rules_after_natural_reload_are_removed(self):
        self.run_script("apply")
        self.fixture.update_state(active_firewall=self.installed())
        self.run_script("remove")
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["active_firewall"], self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})
        self.run_script("remove")
        self.assert_preserved()

    def test_remove_after_reboot_without_custom_table(self):
        self.run_script("apply")
        self.fixture.update_state(active_firewall=self.installed(), tables={})
        self.run_script("remove")
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["active_firewall"], self.firewall)

    def test_symbolic_nft_priority_is_accepted(self):
        self.run_script("apply")
        self.fixture.update_state(symbolic_priority=True)
        self.run_script("check")

    def test_pending_configuration_and_alias_mode_refused(self):
        pending = self.root / "pending-network.json"
        pending.write_text("{}")
        self.run_script("apply", succeeds=False)
        self.assertTrue(pending.exists())
        pending.unlink()
        self.fixture.update_state(addresses={**self.addresses, "10.30.30.210/32": "eth0.2"})
        self.run_script("apply", succeeds=False)
        self.assertEqual(self.installed(), self.firewall)

    def test_unowned_and_modified_rules_refused(self):
        bad = copy.deepcopy(self.firewall)
        bad["foreign"] = {"__type__": "redirect", "src_dip": "10.30.30.0/24"}
        write_json(self.root / "etc/config/firewall", bad)
        self.run_script("apply", succeeds=False)
        write_json(self.root / "etc/config/firewall", self.firewall)
        self.run_script("apply")
        changed = self.installed()
        changed["ato_rte_210_nvr_https"]["src_ip"] = "10.20.0.0/24"
        write_json(self.root / "etc/config/firewall", changed)
        self.run_script("apply", succeeds=False)

    def test_extra_live_table_rule_refused(self):
        self.run_script("apply")
        table = self.fixture.state()["tables"][TABLE]
        self.fixture.update_state(tables={TABLE: table.replace("chain input {", "chain input {\naccept")})
        self.run_script("remove", succeeds=False)

    def test_candidate_broadening_refused_before_commit(self):
        self.fixture.update_state(broaden_forwarding=True)
        self.run_script("apply", succeeds=False)
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})

    def test_atomic_apply_failure_restores_persistent_config(self):
        self.fixture.update_state(failures=[{"command": "nft", "contains": "-f", "skip": 1, "remaining": 1}])
        self.run_script("apply", succeeds=False)
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})

    def test_postapply_verification_failure_restores_both(self):
        self.fixture.update_state(failures=[{"command": "nft", "contains": "list table inet ato_routed_camera", "skip": 1, "remaining": 1}])
        self.run_script("apply", succeeds=False)
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})

    def migrate(self, *, succeeds=True):
        with patch.dict(os.environ, {"ATO_OLD_ROUTES_RETIRED": "yes"}):
            return self.run_script("migrate-lan", succeeds=succeeds)

    def assert_lan_preserved(self):
        network = read_json(self.root / "etc/config/network")
        for key, row in self.fixture.network.items():
            self.assertEqual(network[key], row)
        for address, device in self.addresses.items():
            self.assertEqual(self.fixture.state()["addresses"][address], device)
        for key, row in self.firewall.items():
            self.assertEqual(self.installed()[key], row)
        for event in self.fixture.state()["events"]:
            self.assertNotIn(event["command"], {"ifup", "ifdown", "firewall"})
            self.assertNotIn("reload", event["args"])
            self.assertNotIn("flush", event["args"])

    def test_lan_migration_guards_before_addresses_and_idempotent(self):
        self.run_script("apply")
        self.fixture.update_state(active_firewall=self.installed())
        self.run_script("check-lan")
        self.run_script("migrate-lan", succeeds=False)  # Explicit route-retirement acknowledgement.
        self.run_script("apply-lan", succeeds=False)  # Must not silently change installed VIPs.
        self.migrate()
        state = self.fixture.state()
        table = state["tables"][TABLE]
        self.assertEqual(table.count("ip daddr 10.20.0."), 24)
        self.assertNotIn("ip daddr 10.30.30.", table)
        self.assertEqual(table.count("counter drop"), 2)
        self.assertFalse(any(key.startswith("ato_rte_") for key in state["active_firewall"]))
        for suffix in range(210, 216):
            self.assertEqual(state["addresses"][f"10.20.0.{suffix}/32"], "eth0.2")
            row = read_json(self.root / "etc/config/network")[f"ato_rte_alias_{suffix}"]
            self.assertEqual((row["device"], row["netmask"]), ("@wan", "255.255.255.255"))
        self.run_script("apply-lan")
        self.run_script("check-lan")
        self.assert_lan_preserved()

    def test_lan_address_failure_restores_routed_rules_and_configs(self):
        self.run_script("apply")
        before = copy.deepcopy(self.fixture.state()["tables"])
        firewall = self.installed()
        self.fixture.update_state(active_firewall=firewall, failures=[{"command": "ip", "contains": "addr add 10.20.0.212", "remaining": 1}])
        self.migrate(succeeds=False)
        self.assertEqual(self.fixture.state()["tables"], before)
        self.assertEqual(self.fixture.state()["active_firewall"], firewall)
        self.assertEqual(self.installed(), firewall)
        self.assert_preserved()

    def test_lan_network_commit_failure_restores_firewall(self):
        self.run_script("apply")
        firewall = self.installed()
        table = copy.deepcopy(self.fixture.state()["tables"])
        self.fixture.update_state(failures=[{"command": "uci", "contains": "commit network", "remaining": 1}])
        self.migrate(succeeds=False)
        self.assertEqual(self.installed(), firewall)
        self.assertEqual(self.fixture.state()["tables"], table)
        self.assert_preserved()

    def test_lan_concurrent_network_edit_keeps_matching_new_guards(self):
        self.run_script("apply")
        self.fixture.update_state(concurrent_network_on_failure=True, failures=[{"command": "ip", "contains": "addr add 10.20.0.212", "remaining": 1}])
        result = self.migrate(succeeds=False)
        self.assertIn("Recovery incomplete", result.stderr)
        self.assertEqual(self.installed()["ato_rte_210_nvr_https"]["src_dip"], "10.20.0.210")
        self.assertEqual(self.installed()["ato_rte_input"]["dest_ip"][0], "10.20.0.210")
        network = read_json(self.root / "etc/config/network")
        self.assertIn("other_operator", network)
        self.assertEqual(network["ato_rte_alias_210"]["ipaddr"], "10.20.0.210")
        self.assertIn("ip daddr 10.20.0.210", self.fixture.state()["tables"][TABLE])
        self.assertEqual(self.fixture.state()["addresses"], self.addresses)

    def test_lan_conflicting_alias_and_changed_ownership_refused(self):
        self.fixture.update_state(addresses={**self.addresses, "10.20.0.210/24": "eth0.2"})
        self.run_script("apply-lan", succeeds=False)
        self.fixture.update_state(addresses=self.addresses)
        self.run_script("apply-lan")
        network = read_json(self.root / "etc/config/network")
        network["ato_rte_alias_210"]["device"] = "br-lan"
        write_json(self.root / "etc/config/network", network)
        self.run_script("apply-lan", succeeds=False)

    def test_lan_remove_before_netifd_adoption_and_refuse_loaded_alias(self):
        self.run_script("apply-lan")
        interfaces = self.fixture.state()["interfaces"]
        self.fixture.update_state(interfaces={**interfaces, "ato_rte_alias_210": "10.20.0.210/32"})
        self.run_script("remove-lan", succeeds=False)
        self.fixture.update_state(interfaces=interfaces)
        self.run_script("remove-lan")
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})
        self.assert_preserved()

    def test_open_migration_every_client_uses_frontend_and_preserves_aliases(self):
        self.run_script("apply-lan")
        network = (self.root / "etc/config/network").read_bytes()
        addresses = copy.deepcopy(self.fixture.state()["addresses"])
        self.fixture.update_state(active_firewall=self.installed())
        self.run_script("apply-open-lan", succeeds=False)
        self.run_script("check-open-lan")
        before_events = len(self.fixture.state()["events"])
        self.run_script("migrate-open-lan")
        table = self.fixture.state()["tables"][TABLE]
        self.assertEqual(table.count("dnat ip to "), 12)
        self.assertEqual(table.count("counter drop"), 2)
        self.assertNotIn("saddr", table)
        self.assertNotIn("37777", table)
        self.assertNotIn("dnat ip to 10.30.30.", table)
        own = {key: row for key, row in self.installed().items() if key.startswith("ato_rte_")}
        self.assertEqual(len(own), 14)
        for key, row in own.items():
            self.assertNotIn("_nas_", key)
            self.assertNotIn("src_ip", row)
            if row["__type__"] == "redirect":
                self.assertEqual(row["dest_ip"], "192.168.100.100")
                self.assertIn(row["src_dport"], ("443", "554"))
        self.assertFalse(any(key.startswith("ato_rte_") for key in self.fixture.state()["active_firewall"]))
        self.assertEqual((self.root / "etc/config/network").read_bytes(), network)
        self.assertEqual(self.fixture.state()["addresses"], addresses)
        for event in self.fixture.state()["events"][before_events:]:
            self.assertFalse(event["command"] == "ip" and event["args"][:1] == ["addr"])
        self.run_script("apply-open-lan")
        self.run_script("apply-lan", succeeds=False)
        self.assert_lan_preserved()

    def test_open_failed_verification_restores_restricted_rules(self):
        self.run_script("apply-lan")
        firewall = self.installed()
        network = (self.root / "etc/config/network").read_bytes()
        state = self.fixture.state()
        self.fixture.update_state(active_firewall=firewall, failures=[{"command": "nft", "contains": "list table inet ato_routed_camera", "skip": 1, "remaining": 1}])
        self.run_script("migrate-open-lan", succeeds=False)
        self.assertEqual(self.installed(), firewall)
        self.assertEqual(self.fixture.state()["tables"], state["tables"])
        self.assertEqual(self.fixture.state()["active_firewall"], firewall)
        self.assertEqual(self.fixture.state()["addresses"], state["addresses"])
        self.assertEqual((self.root / "etc/config/network").read_bytes(), network)
        self.assert_lan_preserved()

    def test_open_generated_rules_remove_after_reboot(self):
        self.run_script("apply-open-lan")
        self.fixture.update_state(active_firewall=self.installed(), tables={})
        self.run_script("remove-open-lan")
        self.assertEqual(self.installed(), self.firewall)
        self.assertEqual(self.fixture.state()["active_firewall"], self.firewall)
        self.assertEqual(self.fixture.state()["tables"], {})
        self.assert_preserved()

    def forwarding_snapshot(self):
        state = self.fixture.state()
        return {
            "firewall": self.installed(),
            "network": read_json(self.root / "etc/config/network"),
            **{key: state[key] for key in ("tables", "addresses", "active_firewall")},
        }

    def install_base_live_override(self):
        self.run_script("apply-open-lan")
        tables = self.fixture.state()["tables"]
        for port in (18443, 18554):
            original = f"dnat ip to 192.168.100.100:{port}"
            self.assertEqual(tables[TABLE].count(original), 1)
            tables[TABLE] = tables[TABLE].replace(original, f"dnat ip to 10.20.0.207:{port}")
        self.fixture.update_state(tables=tables)
        return self.forwarding_snapshot()

    def assert_additional_preserves_base(self, before):
        after = self.forwarding_snapshot()
        for package in ("firewall", "network", "active_firewall"):
            self.assertEqual(
                {key: row for key, row in after[package].items() if not key.startswith("ato_add_")},
                before[package],
            )
        self.assertEqual(
            {key: table for key, table in after["tables"].items() if key != "ato_additional_camera"},
            before["tables"],
        )
        additional_addresses = {f"10.20.0.{suffix}/32" for suffix in range(216, 222)}
        self.assertEqual(
            {key: device for key, device in after["addresses"].items() if key not in additional_addresses},
            before["addresses"],
        )
        self.assert_lan_preserved()

    def test_additional_apply_rerun_remove_preserves_base_live_override(self):
        before = self.install_base_live_override()
        self.run_script("check-additional-lan")
        self.assertEqual(self.forwarding_snapshot(), before)
        self.run_script("apply-additional-lan")
        self.assert_additional_preserves_base(before)
        installed = self.forwarding_snapshot()
        own = {key: row for key, row in installed["firewall"].items() if key.startswith("ato_add_")}
        self.assertEqual(len(own), 14)
        for suffix, https, rtsp in (
            (216, 18449, 18560), (217, 18450, 18561), (218, 18451, 18562),
            (219, 18452, 18563), (220, 18453, 18564), (221, 18454, 18565),
        ):
            for name, front_port, back_port in (("https", 443, https), ("rtsp", 554, rtsp)):
                row = own[f"ato_add_{suffix}_nvr_{name}"]
                self.assertEqual((row["src_dip"], row["src_dport"]), (f"10.20.0.{suffix}", str(front_port)))
                self.assertEqual((row["dest_ip"], row["dest_port"]), ("192.168.100.100", str(back_port)))
                self.assertNotIn("src_ip", row)
            self.assertEqual(installed["addresses"][f"10.20.0.{suffix}/32"], "eth0.2")
            self.assertEqual(installed["network"][f"ato_add_alias_{suffix}"]["ipaddr"], f"10.20.0.{suffix}")
        table = installed["tables"]["ato_additional_camera"]
        self.assertEqual(table.count("dnat ip to "), 12)
        self.assertEqual(table.count("counter drop"), 2)
        self.assertNotIn("saddr", table)
        self.run_script("apply-additional-lan")
        self.assertEqual(self.forwarding_snapshot(), installed)
        self.run_script("remove-additional-lan")
        self.assertEqual(self.forwarding_snapshot(), before)
        self.run_script("remove-additional-lan")
        self.assertEqual(self.forwarding_snapshot(), before)
        self.assert_additional_preserves_base(before)

    def test_additional_address_failure_restores_base_and_partial_additions(self):
        before = self.install_base_live_override()
        self.fixture.update_state(failures=[{"command": "ip", "contains": "addr add 10.20.0.218", "remaining": 1}])
        result = self.run_script("apply-additional-lan", succeeds=False)
        self.assertIn("Previous camera configuration restored", result.stderr)
        self.assertEqual(self.forwarding_snapshot(), before)
        self.assert_additional_preserves_base(before)
        address_events = [event["args"][:3] for event in self.fixture.state()["events"] if event["command"] == "ip"]
        for suffix in (216, 217):
            self.assertIn(["addr", "add", f"10.20.0.{suffix}/32"], address_events)
            self.assertIn(["addr", "del", f"10.20.0.{suffix}/32"], address_events)

    def test_additional_generated_rule_cleanup_preserves_base_rules(self):
        self.run_script("apply-open-lan")
        self.fixture.update_state(active_firewall=self.installed())
        before = self.forwarding_snapshot()
        self.run_script("apply-additional-lan")
        self.run_script("check-open-lan")
        self.fixture.update_state(active_firewall=self.installed())
        self.run_script("apply-additional-lan")
        self.assert_additional_preserves_base(before)
        self.assertEqual(self.fixture.state()["active_firewall"], before["active_firewall"])
        self.fixture.update_state(active_firewall=self.installed())
        self.run_script("remove-additional-lan")
        self.assertEqual(self.forwarding_snapshot(), before)
        self.assert_additional_preserves_base(before)

    def test_additional_unknown_owned_section_is_refused(self):
        before = self.install_base_live_override()
        firewall = copy.deepcopy(before["firewall"])
        firewall["ato_add_unrecognized"] = {"__type__": "rule", "target": "ACCEPT"}
        write_json(self.root / "etc/config/firewall", firewall)
        refused = self.forwarding_snapshot()
        result = self.run_script("apply-additional-lan", succeeds=False)
        self.assertIn("Unknown routed section: ato_add_unrecognized", result.stderr)
        self.assertEqual(self.forwarding_snapshot(), refused)

    def test_additional_foreign_overlap_is_refused(self):
        before = self.install_base_live_override()
        for options in ({"src_dip": "10.20.0.216/29"}, {"src_dip": "10.20.0.6", "dest_ip": "10.20.0.221"}):
            with self.subTest(options=options):
                firewall = copy.deepcopy(before["firewall"])
                firewall["foreign_additional_overlap"] = {"__type__": "redirect", **options}
                write_json(self.root / "etc/config/firewall", firewall)
                refused = self.forwarding_snapshot()
                result = self.run_script("apply-additional-lan", succeeds=False)
                self.assertIn("Unowned redirect overlaps camera VIPs", result.stderr)
                self.assertEqual(self.forwarding_snapshot(), refused)


if __name__ == "__main__":
    unittest.main()
