# OpenWrt routing reference: Mango example

Mango can provide virtual-camera addresses and kernel DNAT while `any-to-omada` runs on a NAS or another host. It does not run the translator, manipulate event payloads, decode video or store camera data.

Other suitable OpenWrt routers can perform the same role. Mango is the tested reference hardware; adapt addresses, interfaces and firewall integration for the target device and ensure its forwarding capacity suits the camera traffic.

**An external router is optional.** A Linux/NAS host can own the virtual IPs and publish each IP's 443/554 to distinct listener pairs in one Docker bridge container. A host binary can bind directly to those IPs instead. See [networking and virtual IPs](../../docs/networking.md) for these alternatives; use the profiles below when a separate routing device fits your topology.

**These scripts are fixed deployment reference profiles, not a general-purpose router installer.** They encode particular addresses, interfaces, existing masquerade assumptions and ownership markers. Review the entire chosen script, adapt all constants and rerun its tests for your topology before applying it. Documentation-only IPs in the root example are deliberately not the script's addresses.

The reference platform is GL.iNet GL-MT300N-V2 with GL.iNet 4.3.28 / OpenWrt 22.03.4, firewall4/nftables and wired interface `eth0.2`. Other firmware can have different hooks and firewall behavior.

| Profile | Script | Behavior |
| --- | --- | --- |
| Same-LAN virtual addresses | `camera-routed-forwarding.sh` with `-open-lan` commands | Preferred reference: own /32 aliases, two TCP DNATs per camera, no source-IP restriction, no interface/firewall reload. |
| Additional same-LAN block | Same script with `-additional-lan` commands | Six additional aliases in a separate owned table/namespace. |
| Routed virtual addresses | Same script without suffix | Historical alternative requiring gateway /32 routes; restricted source rules. |
| Alias foundation + forwarding | `camera-aliases.sh`, then `camera-forwarding.sh` | Historical alternative using netifd/firewall reload hooks; unsuitable when unrelated services must not be interrupted. |

Start with the [same-LAN procedure](README-lan-forwarding.md). The [routed profile](README-routed-forwarding.md) and [older alias workflow](README-forwarding.md) are retained for existing deployments and comparison. Do not mix installers or apply one over a profile it does not recognize.

## Before routing

- Reserve virtual addresses outside DHCP and existing static allocations; a failed ping is not proof an address is free.
- Confirm the NAS listener IP/ports, the NVR's location and return routes. The translator must reach physical cameras and the NVR callback endpoint.
- Save router configuration and a recovery path. Inspect pending edits, existing addresses, rules, routes, VPN and service listeners.
- Preserve router management, unrelated forwarding, VPN, monitoring and wireless settings. Use only the chosen script's owned namespaces.
- Keep backups and temporary scripts in RAM, then copy any required backups off the router before reboot. Router backups can contain credentials.

Only a small amount of UCI configuration belongs in Mango flash. The reference scripts check available overlay space and maintain reserve for configuration writes. They do not install packages, services, video components or persistent logs. RAM backups disappear on reboot.

Validate forwarding from the actual client, not only with a backend request originating on Mango. Verify the intended virtual TCP443/554 path, unmatched-port behavior and unchanged unrelated services. Live apply is not proof of reboot persistence; test that separately in a maintenance window.

## Local tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/mango/tests -p 'test_*.py'
sh -n deploy/mango/camera-aliases.sh
sh -n deploy/mango/camera-forwarding.sh
sh -n deploy/mango/camera-routed-forwarding.sh
```

Tests use fake router commands and disposable files. Set `MANGO_TEST_WORK` to an appropriate local directory when needed. Keep that fixture root outside `/tmp`, `/etc`, `/var/lock` and `/overlay`, because the fixture path translation rewrites those locations. Fake tests do not prove actual firmware behavior or end-to-end routing.
