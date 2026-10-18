# Configuration

Use a private copy of [config.example.json](../config.example.json). The strict schema is defined in [internal/config/config.go](../internal/config/config.go), with physical-output settings in [internal/config/controls.go](../internal/config/controls.go).

Unknown fields, duplicate addresses or listeners, repeated source/lens pairs and enabled unverified mappings are rejected. Disabled devices still need valid configuration, but do not resolve credentials or contact cameras. Enabling a source alone collects events without exposing a virtual camera.

Validate from the repository root:

```sh
go run ./cmd/any-to-omada check --config /path/to/private/config.json
```

This checks the configuration structure only. Authentication, network reachability and recorder acceptance require separate verification. Configuration and secrets load at startup; restart after changing them.

## Service settings

| Field | Meaning |
| --- | --- |
| `control_address` | Explicit IPv4 loopback address for health, status and the operator API. The example uses `127.0.0.1:19031`. |
| `storage.directory` | Directory for the bounded event journal, owned by a single running writer. |
| `storage.segment_bytes` | Segment size between 4 and 64 MiB. The example uses 4 MiB. |
| `storage.segments` | Between 2 and 64 retained segments. The example uses 16. |

See [operation and troubleshooting](operations.md) for journal durability and status meanings.

## Sources and virtual cameras

Define each physical camera once in `sources`. Each verified lens gets a separate entry in `cameras`, referencing that source. Lenses on the same physical camera share one event subscription.

| Field | Meaning |
| --- | --- |
| `sources[].host`, `native_port`, `brand` | Physical IPv4 address and event adapter endpoint. The brand selects the adapter below. |
| `sources[].account` | Upstream username and exactly one of `password_file` or `password_env`. |
| `cameras[].source_id`, `source_index` | Exact physical source/lens event mapping. An event index is not an RTSP channel number. |
| `cameras[].verified`, `lens` | Record a checked lens mapping. An enabled camera requires an enabled source, `verified: true`, and a lens other than `unverified`. Use `channel` when the mapping is known without claiming fixed or PTZ mechanics. |
| `cameras[].main_url`, `sub_url` | Distinct, credential-free RTSP URLs on the source IP and a common explicit port. |
| `cameras[].advertised_ip`, `recorder_ip` | Virtual address and logical recorder identity. These fields neither create routing nor restrict clients. |
| `cameras[].management_address`, `rtsp_address` | Distinct IP:port listeners per virtual camera. Use `0.0.0.0` with distinct internal ports in bridge-mode containers, or bind each host virtual IP directly. |
| `cameras[].allowed_transport_peers` | Optional allowlist of up to eight exact IPv4 addresses. Omitted or empty accepts every source IP, including a router's translated peer. |
| `cameras[].account` | Recorder-facing HTTPS/RTSP account. It may reuse the physical account if desired. |
| `cameras[].tls_certificate_file`, `tls_key_file` | Operator-supplied certificate/key. The virtual IP must appear in the certificate SAN. |

Keep passwords out of JSON and stream URLs. Use `password_file` or `password_env` references for both upstream and virtual accounts. Local binary configurations need host paths; container configurations need paths visible inside the container.

Every lens needs a unique virtual IP and listener pair. The schema accepts up to 32 sources and 32 virtual cameras; actual capacity depends on source/NVR limits, bandwidth and host resources. The [six-endpoint](../deploy/nas/all-six.md) and [expansion](../deploy/nas/additional-six.md) examples show how to extend a deployment.

An external router is optional. [Networking and virtual IPs](networking.md) explains host IP aliases, per-IP Docker publishing, direct bindings and OpenWrt routing. The same port can be used on different explicit bind IPs; a wildcard bind on that port overlaps those listeners.

## Source adapters

| Configured brands | Event adapter | Endpoint convention |
| --- | --- | --- |
| `dahua`, `imou`, `amcrest` | Native DVRIP | Usually TCP 37777. Common RTSP path `/cam/realmonitor?channel=1&subtype=0` and subtype `1`. |
| `hikvision`, `annke` | ISAPI alert stream | Camera HTTP port; commonly 80. |
| `reolink`, `axis`, `hanwha`, `uniview`, `tapo`, `bosch`, `vivotek`, `foscam`, `onvif` | ONVIF PullPoint | Camera's enabled ONVIF port; varies by model. |

A brand selector chooses a parser, not a model-wide compatibility guarantee. Dahua/Imou have live verification; ISAPI and generic ONVIF adapters have simulated protocol tests. Use the camera's actual stream URIs, ports and accounts.

Some Dahua cameras reject an otherwise valid stream request with Imou's optional `proto=Onvif` parameter. Do not copy URL parameters between models blindly.

ONVIF provides only the detections a camera exports through it. Native Imou human notifications have been observed while that device's ONVIF interface emitted ordinary motion only. The translator does not infer humans from motion or run a detector. See [detection and events](events.md) for classification and interval behavior.

## Recorder compatibility

The disabled example includes the combination used in successful enrollment: `omada-ipc-observed`, extended identity/video fields, service rows, percent-encoded HTTPS strings and in-stream markers. Its network values are placeholders.

This profile advertises some native services without implementing them. Options default off when omitted. A minimal profile did not cause the tested recorder to request RTSP; which individual additions are essential has not been isolated.

`compatibility.in_stream_markers` inserts observed per-frame `TPLINKMARKERBOX.` metadata into H.264/H.265 while preserving the encoded picture. It supplies an intrusion rule alert without fabricating target boxes. Line-specific marker metadata remains unimplemented. The [protocol reference](omada-protocol.md) distinguishes observed behavior, simulated tests and inference.

Selected time, imaging and detection settings are emulated per virtual camera. Those simulated settings reset on translator restart. Explicit recorder illumination controls instead change physical lamp settings and require successful source readback. Physical controls require separate opt-in blocks; read the [control guide](controls.md) before configuring them.

[Getting started](getting-started.md) В· [Documentation index](../README.md)
