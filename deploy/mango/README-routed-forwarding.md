# Routed virtual addresses: historical reference

The [same-LAN profile](README-lan-forwarding.md) avoids upstream virtual-address routes. This page describes `camera-routed-forwarding.sh` without the `-lan` suffix. Do not apply it over a different installed profile.

The fixed reference uses destination addresses `10.30.30.210–215`, with gateway /32 routes through Mango at `10.20.0.2`. The script does not assign these addresses to interfaces or create gateway routes. Its DNAT selects the backend from traffic delivered by those routes.

The shipped rules restrict frontend HTTPS/RTSP to recorder `10.20.0.150`, forwarding to NAS `192.168.100.100` on 18443–18448 and 18554–18559. Historical NAS-only RTSP/native bypasses select fixed physical sources in `each_rule()`. This is not the open-frontend policy and is not a general inventory format. Review and adapt every address and mapping before use; keep translator source URLs consistent.

## Procedure

Confirm reservations, DHCP exclusions, exact gateway host routes, backend listeners and the existing masquerade return path. Avoid concurrent router edits. Transfer the reviewed script to RAM and run:

```sh
sh /tmp/camera-routed-forwarding.sh check
sh /tmp/camera-routed-forwarding.sh apply
```

`check` verifies ownership, WAN assumptions, pending edits, flash space and candidate syntax without changing committed configuration or packet handling. It cannot prove allocation, upstream routing or NVR compatibility.

`apply` persists 24 redirects and INPUT/FORWARD guards as `ato_rte_*` UCI sections. It validates normal firewall4 rendering without loading it, then atomically installs its separate owned `inet ato_routed_camera` table. Early DNAT selects known backends; guards reject unmatched virtual-address traffic. The script holds the firewall lock and checks fingerprints against conflicting UCI commits.

It performs no `ifup`, netifd/firewall reload, conntrack flush, package installation or service restart. Future firewall4 reloads use persisted mappings. After a reboot the normal UCI rules provide forwarding; a separately owned live table is recreated by reapplying. These mechanisms still require actual reboot/forwarding validation.

Verify from each permitted client, not Mango itself, and check rejection from clients excluded by this profile. Successful backend access does not establish frontend reachability or native enrollment.

## Remove and recover

```sh
sh /tmp/camera-routed-forwarding.sh remove
```

Removal deletes only owned sections, its verified dedicated table and exact matching owned rules inside firewall4. It leaves gateway routes and unrelated services unchanged; existing connections can outlive removal. Coordinate route retirement separately.

Ordinary failures attempt restoration of owned runtime rules and the saved firewall configuration, refusing to overwrite newer edits. Failed recovery reports a private RAM backup directory for inspection. Preserve needed backups off-router before reboot. Power loss, SIGKILL and concurrent administrator edits are outside rollback guarantees.

Only UCI text persists; private backups and candidates remain under `/tmp`. The script checks available flash against the configuration size plus reserve. Do not store video, event logs or binaries on Mango.

## Local checks

```sh
sh -n deploy/mango/camera-routed-forwarding.sh
sh deploy/mango/camera-routed-forwarding.sh render
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/mango/tests -p 'test_camera_routed_forwarding.py'
```

`render` emits the fixed candidate without router changes. Fake-command tests and shell parsing are not live routing tests. Validate the candidate with the target firmware's nftables parser before deployment.
