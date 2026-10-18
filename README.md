# Any to Omada

Present supported third-party camera streams and detections to an Omada NVR as independently addressed virtual cameras. This standalone Go service translates camera protocols, relays encoded video and keeps a bounded event journal. It does not require Home Assistant or [OmadaNvrBridge](https://github.com/RCooLeR/OmadaNvrBridge).

**This is a temporary compatibility workaround while Omada's ONVIF interoperability improves.** Its purpose is to bridge gaps where existing ONVIF integration does not expose the streams, detections or controls needed by the recorder. Native interoperability is preferable when it provides those features. No vendor commitment or timetable for an ONVIF improvement is implied.

This independent, unofficial project is not affiliated with, endorsed by or supported by TP-Link, Omada, ONVIF or the camera manufacturers. It is experimental software, not a certified camera implementation. See [legal and compatibility notices](docs/legal.md), [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Capabilities and evidence

| Area | Implementation and evidence |
| --- | --- |
| Video | Main/sub H.264 and H.265 streams, plus compatible source audio, relayed over RTSP/TCP without transcoding. Dahua/Imou have live verification; twelve virtual cameras and 24 stream paths have been exercised. |
| Omada enrollment | HTTPS management, native authenticated callback, camera identity and RTSP Digest. Tested with an Omada NVR16-8P and translated Imou video; firmware differences can affect compatibility. |
| Events | Motion, human/vehicle/pet motion, line crossing, intrusion and tamper mappings. Motion and human intrusion have recorder-history evidence. Every other model/event combination still needs validation. |
| Multiple lenses | Separate virtual IP, account and streams per verified lens, sharing one event subscription per physical camera. |
| Other source brands | ISAPI and ONVIF adapters have protocol-fake tests, not the same live verification as Dahua/Imou. |
| Settings | Selected time, imaging and detection settings are emulated per virtual camera; they do not change the physical encoder or detection rules. |
| Physical controls | Experimental loopback API for opt-in ONVIF PTZ, native Dahua/Imou white-light pulses and advertised ONVIF alarm-output relays. One Imou camera acknowledged a short PTZ move and Stop; white-light actuation, siren and NVR buttons remain unverified. See [controls](#physical-controls). |

The last confirmed recovery runtime, 0.2.27, was stable with video after PTZ advertisements were disabled. Earlier native preset responses were associated with recorder session failures; the exact recorder failure trigger has not been isolated. Successful video does not establish control compatibility.

## Architecture

```text
Physical cameras -- RTSP + local event protocol --> any-to-omada
                                                      ^
Omada NVR -- virtual camera IP:443/554 -- router DNAT --|
Omada NVR <----------- authenticated callback ---------|
```

Run the translator on a NAS, server or suitable single-board computer. A small OpenWrt router such as Mango can provide IP aliases and kernel DNAT; it does not decode video or translate event payloads. A router is optional if another host provides the required virtual IP and port mappings.

The bundled Mango scripts are reference profiles with fixed addresses from the original deployment, not a generic network installer. Review and replace their topology, interface names and port mappings before using them on another network.

Every virtual stream traverses the translator. If it stops or loses network access, those streams stop. There is no direct-camera failover, cloud adapter, recorder, inference engine or video transcoder in this service.

## Start with one camera

Requirements: Go **1.27.2** to build locally, or Docker with Compose; a reachable camera with local RTSP and a supported event interface; an available NVR channel; and an allocated virtual camera IP. The repository does not assign IPs automatically.

1. Copy `config.example.json` to a private runtime directory. The example is disabled and uses documentation-only addresses. Replace its camera, recorder and virtual addresses, protocol/port, main/sub URLs and credential references.
2. Confirm the physical stream and event source index belong to the intended lens. Set `verified: true` only after that check. `lens: channel` records a mapping without claiming PTZ capability.
3. Supply password files and a certificate/key whose IP SAN includes the virtual IP. Accounts can instead use `password_env`; configure exactly one password reference per account. Never put credentials in stream URLs or tracked JSON.
4. Configure routing to the camera's distinct HTTPS and RTSP listeners. Recorder-facing ports are **443** and **554**; example backend ports are **18443** and **18554**. Allow the translator to connect to the NVR callback port, observed as TCP **6000**.
5. Enable the source and camera in your private JSON, validate it, then start the service. Add the virtual address on a spare NVR channel using **Omada/TP-LINK**, management port **443**, and the virtual account.
6. Check video, then trigger a known detection and verify it in recorder event search. An acknowledged callback is not proof of a saved event.

Build and validate from the repository root:

```sh
go mod verify
go build -o ../any-to-omada-bin ./cmd/any-to-omada
../any-to-omada-bin check --config config.example.json
../any-to-omada-bin version
../any-to-omada-bin serve --config /path/to/private/config.json
```

For a local binary, change container-style storage, TLS and password-file paths to host paths. `check` validates structure without resolving secrets or contacting devices; it cannot establish authentication, reachability or NVR acceptance.

For Docker, copy [compose.example.yaml](compose.example.yaml) and prepare its `config/` and `secrets/` directories. It uses an ordinary Compose bridge network and publishes one camera's ports on loopback. Replace the two host-side `127.0.0.1` bindings with the host's intended LAN address for router/NVR access. The [NAS/container guide](deploy/nas/README.md) covers permissions, multiple cameras and executable updates. No published image is assumed.

## Configuration

The strict schema is in [internal/config/config.go](internal/config/config.go). Unknown fields, duplicate addresses/listeners, repeated source/lens pairs and enabled unverified mappings are rejected. Disabled devices do not resolve credentials or contact cameras. Enabling a source alone collects events without exposing a virtual camera.

| Field | Meaning |
| --- | --- |
| `sources[].host`, `native_port`, `brand` | Physical IP and event adapter endpoint; define each physical source once. |
| `sources[].account` | Upstream account with `password_file` or `password_env`. |
| `cameras[].source_id`, `source_index` | Exact physical source/lens event mapping. An event index is not an RTSP channel number. |
| `main_url`, `sub_url` | Credential-free RTSP URLs on the source IP and a common explicit port. |
| `advertised_ip`, `recorder_ip` | Virtual address and logical recorder identity; neither creates routing nor restricts clients. |
| `management_address`, `rtsp_address` | Distinct listeners per virtual camera; bind `0.0.0.0` inside bridge-mode containers. |
| `allowed_transport_peers` | Optional exact-IP allowlist; omitted/empty accepts every source IP, including a router's translated peer. |
| `cameras[].account` | Recorder-facing HTTPS/RTSP account; it may reuse the physical account if desired. |
| `tls_certificate_file`, `tls_key_file` | Operator-supplied certificate/key; the virtual IP must appear in the certificate SAN. |

The disabled example includes the compatibility combination used in successful enrollment: `omada-ipc-observed`, extended identity/video, service rows, percent-encoded HTTPS strings and in-stream markers. Its network values are placeholders. This profile advertises some native services without implementing them. Options default off when omitted; a minimal profile did not cause the tested recorder to request RTSP. Which individual additions are essential has not been isolated.

`compatibility.in_stream_markers` inserts observed per-frame `TPLINKMARKERBOX.` metadata into H.264/H.265 while preserving the encoded picture. It supplies an intrusion rule alert, not fabricated target boxes. Line-specific marker metadata remains unimplemented. See the evidence-labelled [protocol reference](docs/omada-protocol.md).

For multiple cameras, give every lens a unique virtual IP and listener pair. See [six endpoints](deploy/nas/all-six.md) and [expansion](deploy/nas/additional-six.md). Up to 32 sources and 32 virtual cameras are accepted; actual capacity depends on source/NVR limits, bandwidth and host resources.

## Source adapters

| Configured brands | Event adapter | Endpoint convention |
| --- | --- | --- |
| `dahua`, `imou`, `amcrest` | Native DVRIP | Usually TCP 37777. Common RTSP path `/cam/realmonitor?channel=1&subtype=0` and subtype `1`. |
| `hikvision`, `annke` | ISAPI alert stream | Camera HTTP port; commonly 80. |
| `reolink`, `axis`, `hanwha`, `uniview`, `tapo`, `bosch`, `vivotek`, `foscam`, `onvif` | ONVIF PullPoint | Camera's enabled ONVIF port; varies by model. |

A brand selector chooses a parser, not a model-wide compatibility guarantee. Use the camera's actual stream URIs, ports and accounts. Some Dahua cameras reject an otherwise valid stream request with Imou's optional `proto=Onvif` parameter, so do not copy URL parameters between models blindly.

ONVIF only provides the detections a camera exports through it. Native Imou human notifications have been observed while that device's ONVIF interface emitted ordinary motion only. The translator does not infer humans from motion or run a detector. Unknown/conflicting source tokens stay unrouted; unknown event families stay in the journal.

## Detection and events

| Normalized source event | Omada alarm types |
| --- | --- |
| Motion | `2` |
| Human / vehicle / pet motion | `32` / `33` / `80` |
| Line crossing; human / vehicle / pet | `4`; `36` / `37` / `81` |
| Intrusion; human / vehicle / pet | `5`; `34` / `35` / `82` |
| Tamper | `3` |

Native `Intelligent` notifications are classified only through an explicit, evidence-based device/lens/discriminator mapping. Do not reuse one model's numeric code mapping for another. Explicit IVS classes are preserved; unclassified IVS stays ordinary line crossing or intrusion. Mixed classes become separate alarms.

Start/Stop use wire states `1`/`3`. Pulses create a one-second interval. Rule/source keys preserve overlapping intervals and sparse stops; ambiguous stops are journaled instead of closing unrelated events. Source disconnect schedules closure; callback replacement discards pending events without replay. A DVRIP start without a matching stop can remain open until disconnect. ONVIF intervals expire after five minutes; ISAPI alerts end on inactive or five quiet seconds. Intrusion markers have a separate ten-minute stale limit.

Virtual motion, tamper, intrusion, line-crossing and smart-frame settings filter translated events without reconfiguring physical detection. Simulated time, anti-flicker and sensor-rate values likewise do not change the host clock, exposure or encoded picture; values reset on translator restart.

## Physical controls

Version 0.3.0 adds a loopback operator API for testing controls independently of the recorder. This does **not** add verified Omada NVR buttons or native white-light/siren request handlers. All physical-control blocks are absent from the example.

A direct test on one dual-lens Imou camera acknowledged one short ONVIF pan movement and Stop, with no controller errors. Native channel-scoped lighting reads also succeeded, but a bounded pulse attempt encountered authority-denied code `285278249`; no successful physical light pulse was established. Independent readback confirmed the original lighting settings were retained. The same camera advertised no ONVIF relay outputs. Its built-in siren has no verified local command in this implementation. These observations do not establish support on other models or through the NVR UI.

Opt in per camera only after identifying its actual control endpoint and lens:

```json
{
  "ptz": {"onvif_port": 80, "profile_token": "Profile000", "max_move_seconds": 2},
  "white_light": {"profile": 0, "brightness": 50},
  "alarm_output": {"onvif_port": 80, "relay_token": "RelayOutput1"}
}
```

This is a fragment, not a complete config. Use only supported blocks; do not assume these example profile/relay tokens exist. PTZ also requires `lens: ptz`. White light is limited to Dahua/Imou and the selected native `Lighting_V2` profile (0–7); brightness is 1–100. It uses the camera's `source_index` as the native lighting channel. The alarm output must be an advertised monostable ONVIF relay with an existing device-side delay of 0.1–5 seconds. The service does not reconfigure relay mode or invent a relay for a camera that has none. **An alarm-output relay is not a built-in siren.**

`GET /api/v1/cameras/<camera-id>/controls` reports which controls are configured without contacting hardware. Send JSON to `POST` on the same path for an explicit operation:

| Command body | Result |
| --- | --- |
| `{"command":"white_light_probe"}` | Read the selected native white-light settings without changing them. |
| `{"command":"alarm_probe"}` | Check the advertised relay and its bounded device-side reset. |
| `{"command":"ptz_move","pan":0.2,"tilt":0,"zoom":0}` | Queue movement; axes are -1 to 1 and are checked against discovered capabilities. |
| `{"command":"ptz_stop"}` | Queue Stop, independently of other output operations. |
| `{"command":"white_light_pulse","duration_ms":1000}` | Pulse for 100–5000 ms, then attempt restoration of the previous white-light fields. |
| `{"command":"alarm_pulse"}` | Pulse the relay using its own advertised delay, then attempt an explicit inactive command. |

Use the configured loopback address, for example `http://127.0.0.1:19031/api/v1/cameras/camera-a-lens-1/controls`, and `Content-Type: application/json`. Browser-origin requests are rejected; do not publish or reverse-proxy this operator API. The minimal image has no shell or curl; use an appropriate local diagnostic client in the same network namespace or run a local test instance.

PTZ replies `202` with `move_queued` or `stop_queued`; those states are not hardware acknowledgement. Successful probes/pulses reply `200` with `completed`. Pulse requests wait through the action and cleanup. Unsupported controls return `501`; a busy physical source returns `409`; failures report an unconfirmed final state. A lost connection or power interruption can prevent light restoration or PTZ Stop, so check the physical state after a failure. A white-light restore rereads settings and refuses to overwrite a concurrent change. A monostable relay's own timer bounds its activation even if the translator disappears.

Physical controls remain separate from simulated settings. The source-side ONVIF PTZ backend includes presets, but its Omada-side preset response remains unsupported pending a verified native contract. A `lens: ptz` label alone enables no control.

The previous preset reply did not match the camera UI's nested structure, and recorder sessions failed during preset negotiation. A different guessed success shape is not a verified fix. Keep control advertisements disabled for ordinary deployments and validate opt-ins on a spare channel before daily recording. See [the recorded evidence](docs/omada-protocol.md#84-recorder-resets-during-ptz-negotiation-2026-10-17).

## Operation and troubleshooting

The journal retains redacted native notifications and normalized edges. The example keeps 16 segments of 4 MiB (approximately 64 MiB), with five-second and normal-shutdown flushing. Old owned segments retire across restarts. One writer owns the directory via an OS lock; storage errors stop the service. It is a diagnostic journal, not a durable delivery outbox. Power loss can lose its unsynced tail.

Control endpoints bind only to loopback, by default `127.0.0.1:19031`:

- `/healthz`: process liveness; used by the `healthcheck` command and image healthcheck.
- `/status`: per-camera callback state, counters and failure stage.
- `/readyz`: 200 when at least one authenticated callback connects, otherwise 503. It does not mean all cameras are ready or events are recorded.

`native_alarm_delivery: implemented_unverified` and `recorder_history_verified: false` deliberately avoid declaring recorder storage success from transport activity. `events_written` means a transport write; acknowledgements and searchable history are separate stages. `discovery_shape: not_applicable` is normal outside stream discovery.

Configuration and secrets load at startup; restart after changing them. Transient failures reconnect with bounded backoff. Authentication rejection stops that event subscription's retries until restart. For a failed camera, check source RTSP readiness, callback handshake stage, listener routing and recorder status. Share startup versions and fixed-label errors, not raw authentication payloads or tokens.

## Development

```sh
go mod verify
go vet ./...
go test -race ./...
go run ./cmd/any-to-omada check --config config.example.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/mango/tests -p 'test_*.py'
sh -n deploy/mango/camera-aliases.sh
sh -n deploy/mango/camera-forwarding.sh
sh -n deploy/mango/camera-routed-forwarding.sh
```

Mango tests use fake commands and disposable files; they do not configure a router. Live enrollment, recorder history and hardware controls need separate device validation. Main components are `internal/config`, source event adapters, `cameraevents`, `camerartsp`, `tpmarker`, `omadafront`, `omadalink`, `spakeee`, `eventstore` and `app`. Raw captures, private runtime configuration files, credentials and research-only proxies are not distributed here.
