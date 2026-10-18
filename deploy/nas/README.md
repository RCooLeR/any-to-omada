# NAS and container deployment

The repository is a standalone build context. Its Docker image contains one static Go executable and license notices. It does not depend on the NVR bridge, Home Assistant, a database server or FFmpeg.

## Runtime layout

Keep deployment inputs outside the source checkout:

```text
runtime/
  compose.yaml
  config/
    config.json
    tls/virtual-cameras.crt
    tls/virtual-cameras.key
  secrets/
    camera_password
    virtual_camera_password
  bin/                    # optional versioned executable overrides
```

Use a named volume for `/data`; the event journal lives under `/data/events` in the example. `config/` and `secrets/` are read-only mounts. Both directories must exist before activation, even when all cameras are disabled. Never add credentials, certificates, private keys, captures or journal files to the source/build context.

The image runs as `10001:10001`. A host-specific group can be selected in Compose, for example `10001:10` on a NAS where that group grants the required access. This is a file-permissions setting, not a requirement to change your NAS login user. The configured user/group must read configuration, TLS keys and password files, traverse their directories, execute the binary and write the data volume. Do not solve an unreadable key by making it world-readable.

## Prepare a first deployment

1. Copy `config.example.json` and `compose.example.yaml` into the private runtime layout, renaming them `config/config.json` and `compose.yaml`.
2. Set Compose `build.context` to the standalone checkout if it is outside the runtime directory. Build the image on the intended builder, or load an image you have built for the host architecture. The example's image tag is local; it does not refer to an automatically published registry image.
3. Replace the example's documentation-only IPs and stream URIs. Reserve the virtual IP outside DHCP and assign/route it using your router or host; the service does not create aliases. Confirm the source lens and native event index, set `verified: true`, then enable the source and camera.
4. Supply the password files and an HTTPS certificate/key. The certificate must be current and include the virtual camera IP in its IP SAN. A single certificate can cover several virtual IPs. Preserve an existing valid certificate across ordinary application upgrades.
5. Change the two host-side loopback port bindings to the NAS LAN address used by the router. Add a separate port pair for each additional camera. Keep the control port unpublished.
6. Validate the JSON with the built executable's `check --config` command and validate Compose. Activate only this service through your container manager. Verify the startup version, source stream readiness, NVR enrollment/video and a known event in NVR history.

The default Compose bridge network is sufficient. To join an existing NAS bridge such as `ugos_shared`, declare that network as external and attach only this service. Host networking, privileged mode and Docker socket access are unnecessary. Preserve existing services when adding the translator to a shared Compose project.

## Ports and paths

| Connection | Endpoint |
| --- | --- |
| NVR to virtual camera | TCP 443 for HTTPS management, TCP 554 for RTSP |
| Router to first backend | TCP 18443 and TCP 18554 in the example |
| Translator to NVR | Native callback destination supplied during registration, observed as TCP 6000 |
| Translator to physical camera | Configured RTSP, event protocol and explicitly enabled control ports |
| Local operator/control health | `127.0.0.1:19031` inside the container; never published |

RTSP media uses interleaved TCP; no UDP media range is required. Router DNAT sends each virtual IP's 443/554 to its own backend listener pair. Source cameras are contacted directly by the translator. An `advertised_ip` in JSON alone does not make the address reachable.

The optional `allowed_transport_peers` list checks the peer actually seen by the translator, which can be the router's masqueraded address. An absent or empty list allows every peer. It does not change the logical `recorder_ip` or the virtual IP.

## Environment-based credentials

Instead of `password_file`, an account can reference a private environment variable:

```json
{"username":"admin","password_env":"ATO_CAMERA_PASSWORD"}
```

Add the runtime `.env` path through this service's Compose `env_file`. Docker Compose reading a `.env` for interpolation does not automatically inject all variables into the process. Use `env_file` or explicit `environment` entries. Never print the rendered environment or commit the private file. Virtual and source accounts can use the same reference if desired.

Changing environment values, mounts, networks or published ports requires recreation. A process restart reloads file-based JSON/secrets but does not apply a changed container definition.

## Updating without rebuilding an existing image

The image's entrypoint and healthcheck execute `/any-to-omada`. For an already working deployment, build a static executable for the NAS architecture and mount a versioned file read-only over that path:

```yaml
volumes:
  - type: bind
    source: ./bin/any-to-omada-0.3.0
    target: /any-to-omada
    read_only: true
    bind:
      create_host_path: false
```

1. Test and build the new executable; check its version. Validate a prepared copy of the private runtime JSON with it.
2. Preserve the previous executable path and configuration. Copy the new versioned executable and accompanying license notices, verify its hash and retain executable access for the configured UID/GID.
3. Change only this service's executable bind source. Keep the working credentials, certificate, routing, named volume and other Compose services unchanged.
4. Recreate only the translator using the existing image. Check startup version, source readiness, callback state, video and recorder stability. This briefly reconnects its virtual streams.
5. To roll back, restore the previous executable/configuration pair and recreate only this service. Do not restore previously problematic PTZ advertisements as part of an unrelated rollback.

Copying files does not activate them. Operator-controlled activation is a separate step; a source-tree move needs no live container or router change. Review upgrade-specific configuration requirements before applying a new binary.

## Scaling and verification

See [six endpoints from four physical cameras](all-six.md) and [adding another six](additional-six.md). Each enabled virtual lens eagerly opens up to two upstream profiles; readers share those profiles. One event subscription is shared per physical source. Validate bandwidth and source/NVR session limits before adding a large camera wall.

`/healthz` is liveness; `/readyz` means at least one callback authenticated, not that every camera is working. A callback acknowledgement is not evidence of saved recorder history. Useful diagnostics are the startup version, `camera RTSP profile ready`/`disconnected` messages and callback failure stages. Never share raw authentication exchanges.

Physical controls are opt-in and need independent verification. Default examples keep them disabled; native preset negotiation remains a known compatibility risk. See the [main README](../../README.md#physical-controls).
