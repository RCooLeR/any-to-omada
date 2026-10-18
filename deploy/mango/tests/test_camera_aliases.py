"""Exercise installer safety using local command fakes and disposable files.

Run with Python 3.12+ on Linux/WSL. No root, network, packages or router access
is needed. Only the test copy has its absolute paths rewritten into a fixture root.
The fake firewall validates transaction behavior, not actual firewall4 syntax.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any
import unittest

from fake_router import read_json, write_json

TEST_DIRECTORY = Path(__file__).resolve().parent
INSTALLER = TEST_DIRECTORY.parent / "camera-aliases.sh"
OWNER = "AnyToOmada camera aliases v1"
GUARD = "ato_cam_input"
TRANSACTION_TABLE = "ato_camera_alias_transaction"
CAMERA_ADDRESSES = {f"10.30.30.{suffix}/32" for suffix in range(210, 216)}
BASE_ADDRESSES = {
    "10.20.0.2/24": "eth0.2",
    "10.20.0.4/32": "eth0.2",
    "10.20.0.5/32": "eth0.2",
    "192.168.8.1/24": "br-lan",
}


class CameraAliasesTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "posix":
            self.skipTest("Run these local POSIX shell tests under Linux or WSL.")
        # Avoid /tmp and other rewritten installer prefixes in the fixture root.
        default_work = str(Path.home() / ".cache" / "any-to-omada-tests")
        work = Path(os.environ.get("MANGO_TEST_WORK", default_work))
        work.mkdir(parents=True, exist_ok=True)
        runtime = tempfile.TemporaryDirectory(prefix="camera-alias-tests-", dir=work)
        self.addCleanup(runtime.cleanup)
        self.root = Path(runtime.name)
        for directory in ("bin", "etc/config", "etc/init.d", "var/lock", "tmp", "overlay"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        commands = ("uci", "ip", "ifup", "ifdown", "nft", "ubus", "jsonfilter", "fw4", "sleep")
        for command in (*commands, "firewall"):
            parent = "etc/init.d" if command == "firewall" else "bin"
            target = self.root / parent / command
            shutil.copyfile(TEST_DIRECTORY / "fake_router.py", target)
            target.chmod(0o700)
        source = INSTALLER.read_text(encoding="utf-8")
        for prefix in ("/etc/", "/var/lock/", "/tmp/", "/overlay"):
            self.assertIn(prefix, source)
            source = source.replace(prefix, f"{self.root}{prefix}")
        self.script = self.root / "camera-aliases.sh"
        self.script.write_text(source, encoding="utf-8")
        self.network = {
            "wan": {"__type__": "interface", "proto": "dhcp"},
            "lan": {"__type__": "interface", "ipaddr": "192.168.8.1"},
            "cco_q7": {"__type__": "interface", "ipaddr": "10.20.0.4"},
            "cco_mu6450": {"__type__": "interface", "ipaddr": "10.20.0.5"},
        }
        self.firewall = {
            "defaults": {"__type__": "defaults", "input": "DROP"},
            "gl_admin": {"__type__": "rule", "target": "ACCEPT", "dest_port": "80"},
            "cco_q7_nas_8001": {
                "__type__": "redirect",
                "src_dip": "10.20.0.4",
                "dest_ip": "10.20.0.84",
            },
            "cco_mu6450_nas_8001": {
                "__type__": "redirect",
                "src_dip": "10.20.0.5",
                "dest_ip": "10.20.0.85",
            },
        }
        write_json(self.root / "etc/config/network", self.network)
        write_json(self.root / "etc/config/firewall", self.firewall)
        write_json(
            self.root / "state.json",
            {
                "addresses": BASE_ADDRESSES,
                "interfaces": {
                    "wan": "10.20.0.2/24",
                    "lan": "192.168.8.1/24",
                    "cco_q7": "10.20.0.4/32",
                    "cco_mu6450": "10.20.0.5/32",
                },
                "tables": {},
                "active_firewall": self.firewall,
                "events": [],
                "failures": [],
            },
        )

    def state(self) -> dict[str, Any]:
        return read_json(self.root / "state.json")

    def update_state(self, **changes: Any) -> None:
        state = self.state()
        state.update(changes)
        write_json(self.root / "state.json", state)

    def run_installer(self, action: str, *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
            "MANGO_TEST_ROOT": str(self.root),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            ["/bin/sh", str(self.script), action],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
            env=env,
        )
        details = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        self.assertNotIn("Traceback", result.stderr, details)
        if succeeds:
            self.assertEqual(result.returncode, 0, details)
        else:
            self.assertNotEqual(result.returncode, 0, details)
        return result

    def seed_installed_aliases(self) -> None:
        network = copy.deepcopy(self.network)
        firewall = copy.deepcopy(self.firewall)
        firewall[GUARD] = {
            "__type__": "rule",
            "ato_owner": OWNER,
            "name": "AnyToOmada camera aliases",
            "family": "ipv4",
            "src": "*",
            "proto": "all",
            "target": "DROP",
            "dest_ip": [f"10.30.30.{suffix}" for suffix in range(210, 216)],
        }
        state = self.state()
        for suffix in range(210, 216):
            name = f"ato_cam_{suffix}"
            address = f"10.30.30.{suffix}"
            network[name] = {
                "__type__": "interface",
                "ato_owner": OWNER,
                "device": "@wan",
                "proto": "static",
                "ipaddr": address,
                "netmask": "255.255.255.255",
                "defaultroute": "0",
                "peerdns": "0",
            }
            state["addresses"][f"{address}/32"] = "eth0.2"
            state["interfaces"][name] = f"{address}/32"
        state["active_firewall"] = firewall
        write_json(self.root / "etc/config/network", network)
        write_json(self.root / "etc/config/firewall", firewall)
        write_json(self.root / "state.json", state)

    def assert_unrelated_preserved(self) -> None:
        for package, expected in (("network", self.network), ("firewall", self.firewall)):
            actual = read_json(self.root / "etc/config" / package)
            for name, section in expected.items():
                self.assertEqual(actual[name], section)
        for address, device in BASE_ADDRESSES.items():
            self.assertEqual(self.state()["addresses"][address], device)

    def test_check_does_not_install_aliases_or_guards(self) -> None:
        self.run_installer("check")
        self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
        self.assertEqual(self.state()["tables"], {})
        self.assertEqual(read_json(self.root / "etc/config/network"), self.network)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)

    def test_pending_edits_refuse_before_any_mutation(self) -> None:
        for package in ("network", "firewall", "wireless"):
            with self.subTest(package=package):
                pending = self.root / f"pending-{package}.json"
                pending.write_text('{"unrelated": "pending edit"}', encoding="utf-8")
                result = self.run_installer("apply", succeeds=False)
                self.assertIn(f"pending {package} edits", result.stderr)
                self.assertTrue(pending.exists())
                self.assertEqual(self.state()["tables"], {})
                self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
                self.assert_unrelated_preserved()
                pending.unlink()

    def test_unowned_sections_refuse_before_mutation(self) -> None:
        for package, name in (("network", "ato_cam_210"), ("firewall", GUARD)):
            with self.subTest(package=package):
                path = self.root / "etc/config" / package
                original = path.read_bytes()
                config = read_json(path)
                config[name] = {"__type__": "interface", "name": "Other owner"}
                write_json(path, config)
                expected = path.read_bytes()
                result = self.run_installer("apply", succeeds=False)
                self.assertIn("Unrecognized", result.stderr)
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(self.state()["tables"], {})
                self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
                path.write_bytes(original)

    def test_unowned_active_address_is_not_reassigned(self) -> None:
        addresses = {**BASE_ADDRESSES, "10.30.30.210/24": "other-device"}
        self.update_state(addresses=addresses)
        result = self.run_installer("apply", succeeds=False)
        self.assertIn("already configured outside its owned interface", result.stderr)
        self.assertEqual(self.state()["addresses"], addresses)
        self.assertEqual(self.state()["tables"], {})
        self.assert_unrelated_preserved()

    def test_existing_aliases_without_guard_refuse_changes(self) -> None:
        self.seed_installed_aliases()
        write_json(self.root / "etc/config/firewall", self.firewall)
        before = self.state()["addresses"]
        result = self.run_installer("remove", succeeds=False)
        self.assertIn("without their persistent guard", result.stderr)
        self.assertEqual(self.state()["addresses"], before)
        self.assertEqual(self.state()["tables"], {})

    def test_apply_protects_all_aliases_before_activating_them(self) -> None:
        self.run_installer("apply")
        state = self.state()
        activations = [event for event in state["events"] if event["command"] == "ifup"]
        self.assertEqual(len(activations), 6)
        for event in activations:
            self.assertIn(TRANSACTION_TABLE, event["tables"])
            self.assertEqual(
                set(event["active_firewall"][GUARD]["dest_ip"]),
                {address.split("/")[0] for address in CAMERA_ADDRESSES},
            )
            self.assertEqual(event["active_firewall"][GUARD]["target"], "DROP")
        self.assertTrue(CAMERA_ADDRESSES <= state["addresses"].keys())
        self.assertNotIn(TRANSACTION_TABLE, state["tables"])
        network = read_json(self.root / "etc/config/network")
        for suffix in range(210, 216):
            section = network[f"ato_cam_{suffix}"]
            self.assertEqual(section["netmask"], "255.255.255.255")
            self.assertEqual(section["device"], "@wan")
            self.assertEqual(section["defaultroute"], "0")
            self.assertEqual(section["peerdns"], "0")
        self.assert_unrelated_preserved()

    def test_remove_deactivates_every_alias_before_releasing_guards(self) -> None:
        self.seed_installed_aliases()
        self.run_installer("remove")
        events = self.state()["events"]
        downs = [event for event in events if event["command"] == "ifdown"]
        self.assertEqual(len(downs), 6)
        for event in downs:
            self.assertIn(GUARD, event["active_firewall"])
            self.assertIn(TRANSACTION_TABLE, event["tables"])
        reloads = [event for event in events if event["command"] == "firewall"]
        self.assertEqual(len(reloads), 1)
        self.assertFalse(CAMERA_ADDRESSES & reloads[0]["addresses"].keys())
        self.assertNotIn(GUARD, reloads[0]["active_firewall"])
        self.assertIn(TRANSACTION_TABLE, reloads[0]["tables"])
        self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
        self.assertEqual(self.state()["tables"], {})
        self.assert_unrelated_preserved()

    def test_failed_apply_restores_original_files_and_runtime(self) -> None:
        self.update_state(
            failures=[{"command": "ifup", "contains": "ato_cam_212", "remaining": 1}]
        )
        result = self.run_installer("apply", succeeds=False)
        self.assertIn("previous configuration restored", result.stderr)
        self.assertEqual(read_json(self.root / "etc/config/network"), self.network)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)
        self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
        self.assertEqual(self.state()["tables"], {})
        self.assert_unrelated_preserved()

    def test_incomplete_rollback_retains_temporary_and_persistent_protection(self) -> None:
        self.update_state(
            failures=[
                {"command": "ifup", "contains": "ato_cam_212", "remaining": 1},
                {"command": "ifdown", "contains": "ato_cam_210", "remaining": 1},
                {"command": "ubus", "contains": "network reload", "remaining": 1},
            ]
        )
        result = self.run_installer("apply", succeeds=False)
        self.assertIn("Rollback incomplete", result.stderr)
        state = self.state()
        self.assertIn("10.30.30.210/32", state["addresses"])
        self.assertIn(TRANSACTION_TABLE, state["tables"])
        self.assertIn(GUARD, state["active_firewall"])
        self.assertIn(GUARD, read_json(self.root / "etc/config/firewall"))
        self.assert_unrelated_preserved()

    def test_partial_remove_failure_restores_previously_active_aliases(self) -> None:
        self.seed_installed_aliases()
        before_network = (self.root / "etc/config/network").read_bytes()
        before_firewall = (self.root / "etc/config/firewall").read_bytes()
        self.update_state(
            failures=[{"command": "ifdown", "contains": "ato_cam_212", "remaining": 1}]
        )
        result = self.run_installer("remove", succeeds=False)
        self.assertIn("previous configuration restored", result.stderr)
        self.assertEqual((self.root / "etc/config/network").read_bytes(), before_network)
        self.assertEqual((self.root / "etc/config/firewall").read_bytes(), before_firewall)
        self.assertTrue(CAMERA_ADDRESSES <= self.state()["addresses"].keys())
        self.assertIn(GUARD, self.state()["active_firewall"])
        self.assertEqual(self.state()["tables"], {})
        self.assert_unrelated_preserved()

    def test_stale_transaction_guard_is_preserved(self) -> None:
        existing = {TRANSACTION_TABLE: "Unfinished prior transaction"}
        self.update_state(tables=existing)
        result = self.run_installer("apply", succeeds=False)
        self.assertIn("Transaction guard already exists", result.stderr)
        self.assertEqual(self.state()["tables"], existing)
        self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)

    def test_rendered_guard_after_zone_jump_is_rejected(self) -> None:
        self.update_state(guard_after_jump=True)
        result = self.run_installer("apply", succeeds=False)
        self.assertIn("Rendered INPUT guard is missing or too late", result.stderr)
        self.assertEqual(self.state()["addresses"], BASE_ADDRESSES)
        self.assertEqual(self.state()["tables"], {})
        self.assertEqual(read_json(self.root / "etc/config/network"), self.network)
        self.assertEqual(read_json(self.root / "etc/config/firewall"), self.firewall)


if __name__ == "__main__":
    unittest.main()
