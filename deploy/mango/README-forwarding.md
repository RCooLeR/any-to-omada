# Alias foundation and forwarding: historical reference

The current reference is [same-LAN forwarding](README-lan-forwarding.md), which avoids interface/firewall reloads. This older two-script workflow is retained for existing configurations and tests. Do not mix its owned namespaces with the newer installer.

`camera-aliases.sh` assigns a fixed block of six `/32` aliases to the wired WAN and protects new traffic to the router through those aliases. It does not forward camera traffic. `camera-forwarding.sh` adds a fixed source-restricted NAS/NVR mapping after that foundation exists.

Both scripts encode deployment-specific addresses, interfaces, physical-source mappings and assumptions. Read their source and adapt the entire profile before using them elsewhere. The shipped aliases are `10.30.30.210–215`, requiring upstream host routes through the router. A foreign-subnet alias alone does not attract client traffic.

## Important difference from the current installer

Alias activation/removal invokes netifd operations, and forwarding activation reloads firewall4. On the reference GL.iNet firmware those paths can run shared interface/hotplug hooks and regenerate unrelated rules. A script scoped to camera sections cannot guarantee those firmware hooks leave other services uninterrupted. Use the newer same-LAN method when avoiding that interruption is required.

## Existing-deployment procedure

Reserve the block, verify upstream routes, inspect existing camera-owned state and save a recovery baseline. Keep all concurrent router editors idle. Transfer only the reviewed scripts to router RAM:

```sh
sh /tmp/camera-aliases.sh check
sh /tmp/camera-aliases.sh apply
sh /tmp/camera-forwarding.sh check
sh /tmp/camera-forwarding.sh apply
```

Each `check` inspects ownership and prerequisites without proving address availability or end-to-end traffic. Alias `apply` validates protection before activating interfaces. The forwarding script installs recorder-only HTTPS/RTSP frontends and historical NAS-only physical-camera RTSP/native bypasses. The translator supplies stream-path and event translation; DNAT alone cannot make a camera speak Omada.

Removal uses the reverse order:

```sh
sh /tmp/camera-forwarding.sh remove
sh /tmp/camera-aliases.sh remove
```

Coordinate gateway route retirement separately. Removal touches only the script's recognized owned sections but can invoke the firmware hooks above. Existing connections may persist until closed or expired.

## Recovery and evidence

A temporary INPUT guard protects aliases during transitions. Ordinary errors attempt snapshot restoration; incomplete recovery retains protection and reports the private backup directory. Do not remove a leftover guard or overwrite a newer configuration blindly. Copy any needed RAM backups off the router before reboot; they can contain sensitive configuration.

The scripts install no camera packages, decoder or event storage. Only small UCI definitions persist, subject to their free-flash reserve checks. Fake-command tests establish transaction behavior under the modeled failures, not firmware-wide recovery, reboot persistence or live video. Validate from the actual permitted clients and compare unrelated routing, VPN, management and service state with the baseline.
