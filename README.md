# Any to Omada

A standalone Go service that presents supported IP cameras to an Omada NVR as virtual cameras. It translates camera events, relays encoded video and keeps a local event journal.

**A temporary compatibility workaround while Omada's ONVIF interoperability improves.** No vendor commitment or timetable is implied. This is an independent, experimental project, not an official or certified camera implementation.

## What it does

- Relays main and sub streams over RTSP/TCP without transcoding.
- Maps supported motion, human, vehicle, pet, line-crossing and intrusion events to Omada notifications.
- Exposes separately addressed virtual cameras for verified lenses of multi-lens devices.
- Runs on a NAS, server or suitable single-board computer; optional OpenWrt/Mango routing supplies virtual IPs.

Dahua/Imou streams and selected events have been tested with an Omada NVR16-8P. Other adapters and model/event combinations need their own validation. Physical controls are experimental; see their [tested behavior and limits](docs/controls.md).

## Documentation

| Guide | Contents |
| --- | --- |
| [Getting started](docs/getting-started.md) | Requirements, architecture and first-camera setup |
| [Configuration](docs/configuration.md) | Sources, credentials, lenses, adapters and compatibility options |
| [NAS / Docker](deploy/nas/README.md) | Container setup, permissions and updates |
| [Mango routing](deploy/mango/README.md) | Reference IP forwarding profiles and rollback |
| [Events](docs/events.md) | Detection mappings, event lifecycles and limitations |
| [Physical controls](docs/controls.md) | PTZ, white light and alarm outputs; verification status |
| [Operation](docs/operations.md) | Health, readiness, event storage and troubleshooting |
| [Development](docs/development.md) | Builds, tests and code layout |
| [Protocol reference](docs/omada-protocol.md) | Observed Omada messages, implementation and open questions |
| [Legal and compatibility](docs/legal.md) | Unofficial status, trademarks and usage limitations |

Start with the disabled [example configuration](config.example.json) and [Compose example](compose.example.yaml). Enable one verified camera before expanding the setup. The Mango scripts contain fixed reference topology and must be adapted to your network.

## License

Original code is available under the [MIT license](LICENSE). See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES) for attribution and dependency terms.
