#!/usr/bin/env python3
"""Extend the existing disposable router model for atomic routed-VIP batches."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import sys

from fake_router import Router


class RoutedRouter(Router):
    def event(self, command: str, args: list[str]) -> None:
        # Routed tests verify complete state separately. Keeping command traces
        # without repeated ruleset snapshots avoids quadratic fixture growth.
        plain = args[1:] if args[:1] == ["-q"] else args
        if command == "uci" and plain[0] not in {"commit", "revert"}:
            return
        self.state["events"].append({"command": command, "args": args})

    def should_fail(self, command: str, args: list[str]) -> bool:
        failed = super().should_fail(command, args)
        if failed and self.state.get("concurrent_network_on_failure"):
            from fake_router import read_json, write_json
            path = self.config_path("network")
            config = read_json(path)
            config["other_operator"] = {"__type__": "interface", "proto": "none"}
            write_json(path, config)
        return failed

    def ip(self, args: list[str]) -> int:
        if args[:2] in (["addr", "add"], ["addr", "del"]):
            address, device = args[2], args[4]
            if args[3] != "dev" or device != "eth0.2" or not re.fullmatch(r"10\.20\.0\.(?:21[0-9]|22[01])/32", address):
                raise AssertionError("Only exact new /32 aliases may change")
            if args[1] == "add":
                ip = address.split("/")[0]
                table = "ato_routed_camera" if int(ip.rsplit(".", 1)[1]) < 216 else "ato_additional_camera"
                active = self.state["tables"].get(table, "")
                if not all(ip in active.split(f"chain {chain} {{", 1)[-1] for chain in ("input", "forward")):
                    raise AssertionError("Alias added before verified guards")
                if address in self.state["addresses"]:
                    return 1
                self.state["addresses"][address] = device
            else:
                if self.state["addresses"].pop(address, None) is None:
                    return 1
            return 0
        return super().ip(args)

    def ubus(self, args: list[str]) -> int:
        if len(args) == 3 and args[1].startswith(("network.interface.ato_rte_alias_", "network.interface.ato_add_alias_")):
            if args[1].removeprefix("network.interface.") not in self.state["interfaces"]:
                return 1
        return super().ubus(args)

    def uci(self, args: list[str]) -> int:
        plain = args[1:] if args[:1] == ["-q"] else args
        if plain[0] == "revert" and "." in plain[1]:
            package, section = plain[1].split(".", 1)
            staged = self.config_path(package, staged=True)
            if not staged.exists():
                return 0
            from fake_router import read_json, write_json
            pending = read_json(staged)
            committed = read_json(self.config_path(package))
            if section in committed:
                pending[section] = committed[section]
            else:
                pending.pop(section, None)
            if pending == committed:
                staged.unlink()
            else:
                write_json(staged, pending)
            return 0
        return super().uci(args)

    def rendered_firewall(self, config: dict) -> str:
        lines = ["table inet fw4 {"]
        handle = 1
        for chain in ("input", "forward", "dstnat_wan", "srcnat_wan", "forward_wan"):
            lines.append(f"chain {chain} {{")
            for name, row in config.items():
                if not name.startswith(("ato_rte_", "ato_add_")):
                    continue
                if row["__type__"] == "rule":
                    target = "forward" if row.get("dest") == "*" else "input"
                    if target != chain:
                        continue
                    expression = f'ip daddr {{ {", ".join(row["dest_ip"])} }} counter drop'
                elif chain == "dstnat_wan":
                    source = "192.168.100.0/24" if self.state.get("broaden_forwarding") else row.get("src_ip", "")
                    expression = (f'ip saddr {source} ' if source else "") + f'ip daddr {row["src_dip"]} tcp dport {row["src_dport"]} counter dnat ip to {row["dest_ip"]}:{row["dest_port"]}'
                else:
                    continue
                lines.append(f'{expression} comment "!fw4: {row["name"]}" # handle {handle}')
                handle += 1
            if chain in ("input", "forward"):
                lines.append(f'iifname "eth0.2" jump {chain}_wan')
            if chain == "srcnat_wan":
                lines.append("meta nfproto ipv4 masquerade")
            if chain == "forward_wan":
                lines.append("ct status dnat accept")
            lines.append("}")
        lines.append("}")
        return "\n".join(lines)

    def nft(self, args: list[str]) -> int:
        if args == ["-a", "list", "table", "inet", "fw4"]:
            print(self.rendered_firewall(self.state["active_firewall"]))
            return 0
        if args[:4] == ["list", "chain", "inet", "fw4"]:
            print(self.rendered_firewall(self.state["active_firewall"]))
            return 0
        if args[:3] == ["list", "table", "inet"]:
            if args[3] not in self.state["tables"]:
                return 1
            text = self.state["tables"][args[3]]
            if self.state.get("symbolic_priority"):
                text = text.replace("priority -110", "priority dstnat - 10").replace("priority -10", "priority filter - 10")
            print(text)
            return 0
        check = args[:1] == ["-c"]
        if check:
            args = args[1:]
        if len(args) == 2 and args[0] == "-f":
            program = Path(args[1]).read_text() if args[1] != "-" else sys.stdin.read()
            candidate = copy.deepcopy(self.state)
            lines = iter(program.splitlines())
            for line in lines:
                if not line.strip():
                    continue
                if line in ("delete table inet ato_routed_camera", "delete table inet ato_additional_camera"):
                    if candidate["tables"].pop(line.rsplit(" ", 1)[1], None) is None:
                        return 1
                elif line in ("table inet ato_routed_camera {", "table inet ato_additional_camera {"):
                    table = line.split()[2]
                    if table in candidate["tables"]:
                        return 1
                    block = [line]
                    depth = 1
                    while depth:
                        line = next(lines)
                        depth += line.count("{") - line.count("}")
                        block.append(line)
                    candidate["tables"][table] = "\n".join(block) + "\n"
                elif line.startswith("delete rule inet fw4 "):
                    wanted = int(line.rsplit(" ", 1)[1])
                    # Handles refer to the initial snapshot, not renumbered state.
                    original = self.rendered_firewall(self.state["active_firewall"])
                    match = next(row for row in original.splitlines() if row.endswith(f"# handle {wanted}"))
                    comment = re.search(r'comment "!fw4: (.+?)"', match).group(1)
                    name = next(key for key, row in candidate["active_firewall"].items() if row.get("name") == comment)
                    del candidate["active_firewall"][name]
                elif line.startswith("insert rule inet fw4 "):
                    comment = re.search(r'comment "!fw4: (.+?)"', line).group(1)
                    name, row = next((key, row) for key, row in self.config("firewall").items() if row.get("name") == comment)
                    candidate["active_firewall"][name] = row
                else:
                    raise ValueError(f"Unexpected nft batch operation: {line}")
            if not check:
                self.state = candidate
            return 0
        return super().nft(args)

    def run(self, command: str, args: list[str]) -> int:
        if command == "fw4" and args == ["print"]:
            text = self.rendered_firewall(self.config("firewall"))
            print(re.sub(r" # handle [0-9]+", "", text))
            return 0
        if command == "firewall" or command in {"ifup", "ifdown"} or (command == "ubus" and "reload" in args):
            raise AssertionError("A routed installer must not reload services or interfaces")
        return super().run(command, args)


def main() -> int:
    router = RoutedRouter(Path(os.environ["MANGO_TEST_ROOT"]))
    command = Path(sys.argv[0]).name
    args = sys.argv[1:]
    if router.should_fail(command, args):
        router.event(f"failed:{command}", args)
        router.save()
        print(f"Injected {command} failure", file=sys.stderr)
        return 1
    result = router.run(command, args)
    router.event(command, args)
    router.save()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
