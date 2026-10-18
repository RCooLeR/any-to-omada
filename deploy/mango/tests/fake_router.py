#!/usr/bin/env python3
"""Model router commands for isolated installer transaction tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any


def read_json(path: Path) -> Any:
    """Read a test-owned state file."""
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    """Write a test-owned state file."""
    path.write_text(json.dumps(value), encoding="utf-8")


class Router:
    """Provide a deliberately small, strict OpenWrt command model."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state_path = root / "state.json"
        self.state = read_json(self.state_path)

    def config_path(self, package: str, *, staged: bool = False) -> Path:
        if staged:
            return self.root / f"pending-{package}.json"
        return self.root / "etc" / "config" / package

    def config(self, package: str) -> dict[str, Any]:
        staged = self.config_path(package, staged=True)
        return read_json(staged if staged.exists() else self.config_path(package))

    def save(self) -> None:
        write_json(self.state_path, self.state)

    def event(self, command: str, args: list[str]) -> None:
        uci_args = args[1:] if args[:1] == ["-q"] else args
        if command == "uci" and uci_args[0] not in {"commit", "revert"}:
            return
        self.state["events"].append(
            {
                "command": command,
                "args": args,
                "addresses": dict(self.state["addresses"]),
                "tables": dict(self.state["tables"]),
                "active_firewall": self.state["active_firewall"],
            }
        )

    def should_fail(self, command: str, args: list[str]) -> bool:
        for failure in self.state.get("failures", []):
            if failure["command"] != command or failure["contains"] not in " ".join(args):
                continue
            if failure.get("skip", 0):
                failure["skip"] -= 1
                continue
            if failure["remaining"]:
                failure["remaining"] -= 1
                return True
        return False

    def uci(self, args: list[str]) -> int:
        if args[0] == "-q":
            args = args[1:]
        action, *values = args
        key = values[0] if values else ""
        package, *parts = key.split(".")
        if action == "changes":
            if self.config_path(package, staged=True).exists():
                print(f"{package}.pending=1")
            return 0
        if action in {"commit", "revert"}:
            staged = self.config_path(package, staged=True)
            if staged.exists():
                if action == "commit":
                    write_json(self.config_path(package), read_json(staged))
                staged.unlink()
            return 0
        if action in {"set", "add_list", "reorder"}:
            key, value = key.split("=", 1)
            package, *parts = key.split(".")
        config = self.config(package)
        if action == "show":
            sections = config if not parts else {parts[0]: config[parts[0]]}
            for section, options in sections.items():
                print(f"{package}.{section}={options['__type__']}")
                for option, value in options.items():
                    if option != "__type__":
                        rendered = value if isinstance(value, list) else [value]
                        quoted = " ".join(shlex.quote(item) for item in rendered)
                        print(f"{package}.{section}.{option}={quoted}")
            return 0
        if action == "get":
            if parts[0] not in config:
                return 1
            option = parts[1] if len(parts) > 1 else "__type__"
            if option not in config[parts[0]]:
                return 1
            value = config[parts[0]][option]
            print(" ".join(value) if isinstance(value, list) else value)
            return 0
        if action == "delete":
            if parts[0] not in config:
                return 1
            if len(parts) == 1:
                del config[parts[0]]
            elif parts[1] in config[parts[0]]:
                del config[parts[0]][parts[1]]
            else:
                return 1
        elif action == "set":
            if len(parts) == 1:
                config[parts[0]] = {"__type__": value}
            else:
                config[parts[0]][parts[1]] = value
        elif action == "add_list":
            config[parts[0]].setdefault(parts[1], []).append(value)
        elif action == "reorder":
            section = config.pop(parts[0])
            entries = list(config.items())
            entries.insert(int(value), (parts[0], section))
            config = dict(entries)
        else:
            raise ValueError(f"Unsupported uci arguments: {args!r}")
        write_json(self.config_path(package, staged=True), config)
        return 0

    def ip(self, args: list[str]) -> int:
        if args[:3] in (["-4", "addr", "show"], ["-4", "address", "show"]):
            for address, device in self.state["addresses"].items():
                if "dev" not in args or args[args.index("dev") + 1] == device:
                    print(f"2: {device} inet {address} scope global {device}")
            return 0
        if args[:4] == ["-4", "-o", "addr", "show"]:
            return self.ip(["-4", "addr", "show", *args[4:]])
        raise ValueError(f"Unsupported ip arguments: {args!r}")

    def interface(self, command: str, args: list[str]) -> int:
        name = args[-1]
        network = self.config("network")
        if command == "ifup":
            if name not in network:
                return 1
            cidr = f"{network[name]['ipaddr']}/32"
            self.state["addresses"][cidr] = "eth0.2"
            self.state["interfaces"][name] = cidr
        elif name in self.state["interfaces"]:
            cidr = self.state["interfaces"].pop(name)
            self.state["addresses"].pop(cidr, None)
        return 0

    def ubus(self, args: list[str]) -> int:
        if args == ["call", "network", "reload"]:
            for name in list(self.state["interfaces"]):
                if name not in self.config("network"):
                    self.interface("ifdown", [name])
            return 0
        if len(args) == 3 and args[0] == "call" and args[2] == "status":
            name = args[1].removeprefix("network.interface.")
            cidr = self.state["interfaces"].get(name)
            print(
                json.dumps(
                    {
                        "up": cidr is not None,
                        "l3_device": "eth0.2",
                        "ipv4-address": [{"address": cidr.split("/")[0]}]
                        if cidr
                        else [],
                    }
                )
            )
            return 0
        raise ValueError(f"Unsupported ubus arguments: {args!r}")

    def rendered_firewall(self, config: dict[str, Any]) -> str:
        lines = ["table inet fw4 {", "chain input {"]
        if self.state.get("guard_after_jump"):
            lines.append('iifname "eth0.2" jump input_wan')
        for section in config.values():
            if (
                section.get("__type__") == "rule"
                and section.get("src") == "*"
                and section.get("target") == "DROP"
                and section.get("enabled", "1") == "1"
                and not self.state.get("omit_guard")
            ):
                addresses = ", ".join(section.get("dest_ip", []))
                name = section["name"]
                lines.append(f'ip daddr {{ {addresses} }} drop comment "!fw4: {name}"')
        lines.extend(['iifname "eth0.2" jump input_wan', "}", "chain dstnat_wan {"])
        for section in config.values():
            if section.get("__type__") != "redirect" or "ato_owner" not in section:
                continue
            if section.get("enabled", "1") != "1" or self.state.get("omit_forwarding"):
                continue
            source = section.get("src_ip", "0.0.0.0/0")
            if self.state.get("broaden_forwarding"):
                source = "192.168.100.0/24"
            lines.append(
                f'ip saddr {source} ip daddr {section["src_dip"]} '
                f'tcp dport {section["src_dport"]} counter '
                f'dnat ip {section["dest_ip"]}:{section["dest_port"]} '
                f'comment "!fw4: {section["name"]}"'
            )
        lines.extend(["}", "chain srcnat_wan {"])
        for section in config.values():
            if section.get("__type__") == "zone" and section.get("name") == "wan":
                if section.get("masq") == "1":
                    lines.append("meta nfproto ipv4 masquerade")
        lines.extend(["}", "}"])
        return "\n".join(lines)

    def nft(self, args: list[str]) -> int:
        if args[:4] == ["list", "chain", "inet", "fw4"] and args[4] in {
            "input", "dstnat_wan", "srcnat_wan"
        }:
            print(self.rendered_firewall(self.state["active_firewall"]))
            return 0
        if args[:3] == ["list", "table", "inet"]:
            table = args[3]
            if table not in self.state["tables"]:
                return 1
            print(self.state["tables"][table])
            return 0
        if args[:3] == ["delete", "table", "inet"]:
            return 0 if self.state["tables"].pop(args[3], None) is not None else 1
        if args == ["-f", "-"]:
            program = sys.stdin.read()
            words = program.split()
            table = words[words.index("inet") + 1]
            if table in self.state["tables"]:
                return 1
            self.state["tables"][table] = program
            return 0
        raise ValueError(f"Unsupported nft arguments: {args!r}")

    def run(self, command: str, args: list[str]) -> int:
        if command == "uci":
            return self.uci(args)
        if command == "ip":
            return self.ip(args)
        if command in {"ifup", "ifdown"}:
            return self.interface(command, args)
        if command == "nft":
            return self.nft(args)
        if command == "ubus":
            return self.ubus(args)
        if command == "jsonfilter" and args[0] == "-e":
            status = json.load(sys.stdin)
            values = {
                "@.up": "true" if status["up"] else "false",
                "@.l3_device": status["l3_device"],
                '@["ipv4-address"][0].address': (
                    status["ipv4-address"][0]["address"]
                    if status["ipv4-address"]
                    else ""
                ),
            }
            print(values[args[1]])
            return 0
        if command == "id" and args == ["-u"]:
            print("0")
            return 0
        if command == "fw4" and args == ["check"]:
            return 0
        if command == "fw4" and args == ["print"]:
            print(self.rendered_firewall(self.config("firewall")))
            return 0
        if command == "firewall" and args == ["reload"]:
            self.state["active_firewall"] = self.config("firewall")
            return 0
        if command == "sleep":
            return 0
        raise ValueError(f"Unsupported command: {command} {args!r}")


def main() -> int:
    """Dispatch only supported fake commands and persist their event trace."""
    router = Router(Path(os.environ["MANGO_TEST_ROOT"]))
    command = Path(sys.argv[0]).name
    args = sys.argv[1:]
    if router.should_fail(command, args):
        router.event(f"failed:{command}", args)
        router.save()
        print(f"Injected {command} failure", file=sys.stderr)
        return 1
    code = router.run(command, args)
    router.event(command, args)
    router.save()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
