# Virtual IPs and optional OpenWrt routing

An external routing device is optional. `any-to-omada` can run on a PC, NAS or Linux host that owns the virtual camera addresses itself. One Ethernet interface can have multiple IPv4 addresses, and one translator process or container can serve all configured cameras.

When using a separate router, any suitable OpenWrt device can supply virtual IPs and port forwarding. GL.iNet Mango is the tested reference example, not a required model.

The application separates `advertised_ip` (the address the NVR uses) from `management_address` and `rtsp_address` (where the process listens). It does not assign addresses, configure VLANs or install routes. These are host/network configuration tasks.

## Choose a deployment

| Host | Approach |
| --- | --- |
| Linux / Raspberry Pi | Persistent additional addresses on the appropriate Ethernet/VLAN interface; run a native binary or publish Docker ports on those addresses. |
| Windows | Additional IPv4 addresses on the adapter; a native translator binary can bind each address directly. Configure Windows Firewall for the intended connections. |
| Linux-based NAS | Host IP aliases with Docker bridge port publishing, if the NAS provides a persistent way to manage those addresses. OS support does not guarantee a supported NAS UI workflow. |

Linux NetworkManager supports a list of IPv4 addresses per connection. Windows supports multiple addresses through its networking APIs; however, `New-NetIPAddress` disables DHCP on an interface where DHCP is enabled, so do not apply it blindly to a working management adapter. See the [NetworkManager reference](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html) and [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netipaddress).

For UGREEN UGOS, the persistent alias configuration procedure has not been verified by this project. Confirm how the installed firmware preserves addresses across reboot and upgrades before replacing an existing router setup.

## Optional OpenWrt router

The router owns the virtual camera IPs and forwards their TCP 443/554 traffic to the translator's per-camera listener ports. Translation, source event subscriptions and video relay run on the NAS/PC/Linux host. No translator or transcoder needs to run on the router.

Choose a router with persistent interface aliases, DNAT/masquerade support, suitable VLAN or routed connectivity, and enough forwarding capacity for the combined camera streams. CPU, Ethernet port speed and firmware configuration differ between models; sharing OpenWrt does not guarantee the same throughput.

The supplied [OpenWrt routing reference](../deploy/mango/README.md) was tested on GL-MT300N-V2 with firewall4/nftables. Its scripts contain that deployment's addresses, interface names and ownership markers. Adapt them to another router's interfaces, firewall generation and topology; they are not a universal OpenWrt installer. Keep unrelated router management, VPN and forwarding intact.

OpenWrt documents [multiple addresses on an interface](https://openwrt.org/docs/guide-user/network/ipv4/examples#multiple_ip_addresses) and [DNAT/SNAT configuration](https://openwrt.org/docs/guide-user/firewall/fw3_configurations/fw3_nat). These are platform capabilities; this project's model-specific reference is only one way to use them.

## Network reachability comes first

Virtual addresses must be allocated outside DHCP and other static assignments. Adding an address to the host does not connect the host to another VLAN.

If NAS management belongs to one VLAN and the virtual cameras belong to another, use an Ethernet interface on the camera VLAN, an allowed tagged VLAN interface, or an explicitly designed routed/proxy-ARP arrangement. The NVR must be able to resolve or route each virtual address to the new host, and return traffic must have a valid path. A normal route on the NAS alone does not change where the NVR sends traffic.

The host also needs access to physical camera streams and event services. The translator must reach the NVR's native callback endpoint, observed as TCP 6000 on the tested recorder. Removing Mango does not remove these requirements.

## Docker bridge with host IP aliases

Keep one container and its existing bridge network. Assign the virtual addresses persistently to the host first, then publish each address's TCP 443 and 554 to its own pair of container listeners. Docker supports [publishing on a specific host IP](https://docs.docker.com/engine/network/port-publishing/).

```text
Physical cameras -- RTSP + local events --> any-to-omada container
                                                   ^
NVR -- host virtual IP:443/554 -- Docker publish ----|
NVR <------------ native alarm callback ------------|
```

The following addresses are documentation-only examples; replace them with reserved addresses on the intended network.

| Camera | Host HTTPS endpoint | Host RTSP endpoint | Container listener ports |
| --- | --- | --- | --- |
| A | `192.0.2.210:443` | `192.0.2.210:554` | `18443`, `18554` |
| B | `192.0.2.211:443` | `192.0.2.211:554` | `18444`, `18555` |

Replace the translator service's `ports` list with matching mappings. This is a fragment for the existing [Compose service](../compose.example.yaml), not a complete deployment file:

```yaml
services:
  any-to-omada:
    ports:
      - "192.0.2.210:443:18443/tcp"
      - "192.0.2.210:554:18554/tcp"
      - "192.0.2.211:443:18444/tcp"
      - "192.0.2.211:554:18555/tcp"
```

Keep these fields in each full camera configuration aligned:

```json
[
  {
    "advertised_ip": "192.0.2.210",
    "management_address": "0.0.0.0:18443",
    "rtsp_address": "0.0.0.0:18554"
  },
  {
    "advertised_ip": "192.0.2.211",
    "management_address": "0.0.0.0:18444",
    "rtsp_address": "0.0.0.0:18555"
  }
]
```

These are partial camera entries: retain source/lens mapping, accounts, certificate paths and other required fields from the [configuration guide](configuration.md). The certificate SAN must contain the advertised virtual IP.

Host networking and one-container-per-camera are unnecessary. The container still listens on unprivileged internal ports. Keep the operator API on container loopback, unpublished, and retain the existing data volume and credential references.

Check for existing services on the selected addresses/ports. A service bound to `0.0.0.0:443`, such as a NAS management UI, can conflict with publishing HTTPS on an alias. A dedicated interface alone does not remove a wildcard listener conflict. A Linux VM or a separately addressed container network is an alternative to changing the NAS management listener.

With multiple Compose files, port lists can merge. Check the effective configuration through the operator's normal workflow so obsolete mappings are removed rather than retained. Creating host aliases and changing published ports are separate operations; recreating a container does not create host aliases.

## Direct host binary

With the virtual IPs assigned to the host, configure listeners directly on each address:

| Camera | `advertised_ip` | `management_address` | `rtsp_address` |
| --- | --- | --- | --- |
| A | `192.0.2.210` | `192.0.2.210:443` | `192.0.2.210:554` |
| B | `192.0.2.211` | `192.0.2.211:443` | `192.0.2.211:554` |

The validator permits the same port on different explicit IPs. It rejects overlapping listeners, including a wildcard listener on the same port. Addresses must exist in the process's network namespace before startup.

On Linux, direct binding to 443/554 may require low-port binding permission, depending on host policy. Configure that permission for the service instead of defaulting the application to root. Docker bridge publishing avoids low-port binding inside the translator container.

Use host filesystem paths for storage, certificates and password files. Ensure firewall and return routes allow management, RTSP and callbacks. See [running a local binary](getting-started.md#run-a-local-binary).

## Macvlan / ipvlan alternatives

Linux Docker also offers macvlan and ipvlan networks to give containers addresses on an attached network. They can avoid publishing through a host management address but require explicit interface, address and routing design. Creating one network does not automatically assign every camera's virtual IP to the translator.

Docker's macvlan driver is supported on native Linux hosts, not Docker Desktop for Windows or Mac, Windows Docker Engine, or rootless Docker. Macvlan also isolates containers from their host by default; a host-side interface or another network is needed when that communication is required. See [Docker's macvlan and ipvlan guidance](https://docs.docker.com/engine/network/drivers/macvlan/).

For a host that can persist aliases and publish their ports, the existing Docker bridge arrangement is the more direct starting point.

## Move an existing router deployment

1. Record the current address-to-camera mapping, external ports, backend listeners and callback path. Keep a rollback configuration for existing routing.
2. Prepare host address persistence and network access. Check address allocation and listener conflicts before applying changes.
3. Move one virtual address first. Remove its ownership from the old router before assigning it to the new host; two devices must not answer for the same IP. Expect a brief reconnect and allow neighbor/ARP caches to refresh.
4. Keep the virtual IP, external 443/554 ports and account unchanged where possible. Replacing an advertised IP also requires a matching certificate and NVR configuration change.
5. From the NVR's network, verify HTTPS/RTSP reachability, video, callback authentication and a known detection in recorder history. A successful test from the host itself is insufficient.
6. Expand after the first channel works. Verify persistence across a planned host restart before retiring the old routing. To roll back, remove the new host's ownership first, then restore the former router ownership and mappings.

If `allowed_transport_peers` was configured for the old router's masqueraded address, review it before switching: the translator may now see the NVR's address or a different translated peer. Preserve an absent/empty list when no source-IP filtering is intended.

Direct listeners and per-IP Docker publishing match the current application configuration model. They are deployment options, not a claim that a particular NAS firmware or topology has been tested. All virtual video still traverses the translator; stopping it interrupts those streams regardless of whether Mango is present.

[Getting started](getting-started.md) · [NAS / Docker](../deploy/nas/README.md) · [OpenWrt reference](../deploy/mango/README.md) · [Documentation index](../README.md)
