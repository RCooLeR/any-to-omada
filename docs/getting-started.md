# Getting started

Start with one camera and a spare NVR channel. You need a reachable camera with local RTSP and a supported [event adapter](configuration.md#source-adapters), an allocated virtual camera IP, and either Go **1.27.2** or Docker with Compose. The service does not assign IP addresses.

## What has been tested

| Area | Implementation and evidence |
| --- | --- |
| Video | Main/sub H.264 and H.265 streams, plus compatible source audio, relayed over RTSP/TCP without transcoding. Dahua/Imou have live verification; twelve virtual cameras and 24 stream paths have been exercised. |
| Enrollment | HTTPS management, authenticated native callback, camera identity and RTSP Digest. Tested with an Omada NVR16-8P and translated Imou video; firmware differences can affect compatibility. |
| Events | Motion, human/vehicle/pet motion, line crossing, intrusion and tamper mappings. Motion and human intrusion have recorder-history evidence. Other model/event combinations still need validation. |
| Multiple lenses | Separate virtual IP, account and streams per verified lens, sharing one event subscription per physical camera. |
| Other source brands | ISAPI and ONVIF adapters have simulated protocol tests, not the same live verification as Dahua/Imou. |
| Settings | Selected time, imaging and detection settings are emulated per virtual camera. Explicitly enabled illumination controls change supported physical lamp settings and verify source readback. Encoder and detection settings remain virtual. |
| Physical controls | One Imou camera has operator-confirmed NVR PTZ movement on 0.3.1. The 0.4.0 source controls have alarm activation and Stop acknowledgements on four cameras, with sound and flashing light physically confirmed on one. One 20% white-light test completed for one second with source readback and restoration. NVR rendering of the new 0.4.0 controls and movement on other cameras still need testing; see [physical controls](controls.md). |

Successful video does not establish control compatibility. Enable each control only for its verified source and lens, then test it on one recorder channel before expanding. Presets remain unsupported; the [control guide](controls.md#recorder-compatibility) explains the recorder failures associated with earlier preset responses and the evidence required for each control.

## Plan the network path

```text
Physical cameras -- RTSP + local event protocol --> any-to-omada
                                                      ^
Omada NVR -- virtual IP:443/554 -- host or router -----|
Omada NVR <----------- authenticated callback ---------|
```

Run the translator on a NAS, server or suitable single-board computer. A small OpenWrt router such as Mango can provide IP aliases and kernel DNAT. It does not decode video or translate event payloads. A router is optional if another host provides the virtual IPs and port mappings.

See [networking and virtual IPs](networking.md) for Linux, Windows and NAS address options, per-IP Docker publishing, and optional OpenWrt routers. Mango is one tested router example.

Each virtual camera needs its own IP and HTTPS/RTSP listener pair:

| Connection | Port |
| --- | --- |
| NVR to virtual camera management | TCP 443 |
| NVR to virtual camera video | TCP 554 |
| Docker publishing or router DNAT to example translator listeners | TCP 18443 and 18554 |
| Translator to NVR native callback | TCP 6000, as observed on the tested recorder |

The [Mango routing profiles](../deploy/mango/README.md) contain fixed addresses from the original deployment. Review and replace their topology, interface names and port mappings before using them on another network.

Every virtual stream traverses the translator. If it stops or loses network access, those streams stop. There is no direct-camera failover, cloud adapter, recorder, inference engine or video transcoder in this service.

## Prepare one camera

1. Copy [config.example.json](../config.example.json) to a private runtime directory. The example is disabled and uses documentation-only addresses. Replace the camera, recorder and virtual addresses, event port, main/sub URLs and credential references.
2. Confirm that the physical streams and event source index belong to the intended lens. Set `verified: true` only after that check. `lens: channel` records the mapping without claiming PTZ capability.
3. Supply password files and a certificate/key whose IP SAN includes the virtual IP. Accounts can instead use `password_env`; configure exactly one password reference per account. Keep credentials out of stream URLs and tracked JSON.
4. Configure routing to the camera's distinct HTTPS and RTSP listeners. Allow the translator to reach the NVR callback port.
5. Enable the source and camera in the private JSON, validate it, then start the service using one of the methods below.
6. Add the virtual address on a spare NVR channel using **Omada/TP-LINK**, management port **443**, and the virtual account.
7. Check video, then trigger a known detection and verify it in recorder event search. An acknowledged callback does not prove that the recorder saved an event.

See [configuration](configuration.md) for field meanings, adapter selection and the compatibility profile.

## Run a local binary

Build and validate from the repository root:

```sh
go mod verify
go build -o ../any-to-omada-bin ./cmd/any-to-omada
../any-to-omada-bin check --config config.example.json
../any-to-omada-bin version
../any-to-omada-bin serve --config /path/to/private/config.json
```

Change the example's container-style storage, TLS and password-file paths to host paths before serving a local configuration. `check` validates structure without resolving secrets or contacting devices. It cannot establish authentication, reachability or NVR acceptance.

## Run in a container

Use [compose.example.yaml](../compose.example.yaml) and prepare its `config/` and `secrets/` directories. The example builds from the source tree; no published image is assumed.

The Compose service uses an ordinary bridge network and publishes one camera's ports on loopback. Replace the two host-side `127.0.0.1` bindings with the host's intended LAN address for router/NVR access. Keep the operator API on container loopback unpublished.

Follow the [NAS/container guide](../deploy/nas/README.md) for permissions, multiple cameras and executable updates. Once running, use [operation and troubleshooting](operations.md) to interpret health and callback status.

[Documentation index](../README.md)
