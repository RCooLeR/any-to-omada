# Same-LAN camera VIP reference

Use `camera-routed-forwarding.sh` with its `-open-lan` commands for aliases on the NVR's subnet. Read the [routing overview](README.md) first: this script contains a fixed reference topology that must be reviewed and adapted before use elsewhere.

As shipped, the first block is `10.20.0.210–215`, on wired `eth0.2`; the router primary address is `10.20.0.2`. Each virtual IP's TCP443/554 forwards to host `192.168.100.100`. Backend ports are 18443/18554 for the first address, increasing together through 18448/18559. Physical camera selection belongs to translator JSON, not these open-frontend rules.

The reference profile accepts every source IP on those two frontend ports. It contains no `ip saddr` expressions or UCI `src_ip` options. Unmatched traffic to the aliases is dropped; the router's normal management address is outside this camera profile. Existing WAN masquerade provides the return path. No UDP media or discovery forwarding is installed.

## Fresh installation and inspection

Reserve the whole block and verify NAS listeners and certificate SANs first. Keep configuration editors idle while a transaction runs. Transfer the reviewed script to router RAM through the existing management path:

```sh
sh /tmp/camera-routed-forwarding.sh check-open-lan
sh /tmp/camera-routed-forwarding.sh apply-open-lan
sh /tmp/camera-routed-forwarding.sh check-open-lan
```

`check-open-lan` verifies ownership, prerequisites, available flash and candidate syntax. It does not apply packet handling, prove allocation or establish reachability. `apply-open-lan` persists 12 redirects and INPUT/FORWARD guards under `ato_rte_*`, with six `ato_rte_alias_*` network sections. It atomically replaces only its owned `inet ato_routed_camera` table.

After the guards are verified, direct `ip addr add <VIP>/32 dev eth0.2` activates the exact aliases. Mango answers ARP for them and DNAT selects the backend. No `ifup`, `ifdown`, netifd reload, firewall reload, service restart, sysctl change or global conntrack flush occurs.

Existing unrelated configuration and sessions are preserved. Direct aliases are immediately active, while netifd adopts their persisted sections on a future normal reload/reboot. Until that adoption, a WAN bounce may remove them; rerunning `apply-open-lan` restores missing exact aliases after checking protection. Reboot persistence still needs a device test.

## Explicit migrations

An installed source-restricted same-LAN profile requires the explicit migration:

```sh
sh /tmp/camera-routed-forwarding.sh check-open-lan
sh /tmp/camera-routed-forwarding.sh migrate-open-lan
```

It replaces the recognized restricted redirects with open frontend redirects and removes the obsolete camera-owned bypasses. `apply-open-lan` refuses to silently perform that policy change. Existing conntrack entries expire naturally.

For the older routed-subnet profile, first retire only its old gateway /32 routes and verify retirement. A leftover gateway route can loop packets after the address migration. Update the translator's advertised addresses and certificate separately. The explicit guarded conversion is:

```sh
sh /tmp/camera-routed-forwarding.sh check-lan
ATO_OLD_ROUTES_RETIRED=yes sh /tmp/camera-routed-forwarding.sh migrate-lan
sh /tmp/camera-routed-forwarding.sh migrate-open-lan
```

`migrate-lan` retains the historical restricted policy; the final command selects open frontends. Never acknowledge route retirement without verifying it. Do not change physical-camera subnet routing.

## Six additional LAN VIPs

The shipped `-additional-lan` profile manages `10.20.0.216–221`, forwarding to HTTPS18449–18454 and RTSP18560–18565 on the same backend host. Its `inet ato_additional_camera` table, `ato_add_*` firewall sections and `ato_add_alias_*` addresses are independent of the first six. Both profiles share transaction locks and preserve one another's state.

```sh
sh /tmp/camera-routed-forwarding.sh check-additional-lan
sh /tmp/camera-routed-forwarding.sh apply-additional-lan
sh /tmp/camera-routed-forwarding.sh check-additional-lan
sh /tmp/camera-routed-forwarding.sh check-open-lan
```

Reserve the extra block, prepare certificate SANs, publish its twelve backend ports and configure the translator before applying routing. The profile permits all sources on TCP443/554, with no physical-camera bypass. It uses the same guard-before-alias ordering without service reloads.

## Removal, rollback and validation

Before netifd adopts aliases, remove only the relevant block with `remove-open-lan` or `remove-additional-lan`. Removal deletes exact addresses before deleting their guards and configuration. Once netifd owns any alias, removal refuses rather than invoking potentially disruptive interface hooks; use a separate maintenance procedure.

On ordinary failures, rollback removes only addresses added by that attempt and restores verified owned rules/configuration snapshots. Fingerprints detect conflicting configuration edits. If a newer edit is detected or an address cannot be removed, protection is retained and recovery is reported incomplete. Inspect the reported private `/tmp` backup before retrying; never restore an old whole-router snapshot over later changes.

SIGKILL, power loss and concurrent administrator edits are outside transactional guarantees. Existing translated connections can remain until closed or timed out. Free-flash checks reserve current configuration sizes, alias overhead and 64 KiB of headroom; they do not certify flash health.

Test virtual TCP443/554 from a normal client and verify NVR video on a spare channel. A request from Mango to a NAS listener validates only the backend leg. Check that other alias ports stay unavailable and compare unrelated addresses/routes, forwarding, VPN, service listeners and wireless state against the baseline. Do not reboot or flush conntrack merely to test new mappings.
