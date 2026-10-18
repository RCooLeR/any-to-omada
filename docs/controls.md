# Physical controls

Version 0.3.0 adds a loopback operator API for testing opt-in controls independently of the recorder. It does **not** add verified Omada NVR buttons or native white-light/siren request handlers. All physical-control blocks are absent from [config.example.json](../config.example.json).

## Hardware evidence

A direct test on one dual-lens Imou camera acknowledged one short ONVIF pan movement and Stop, with no controller errors.

Native channel-scoped lighting reads also succeeded, but a bounded pulse attempt encountered authority-denied code `285278249`. No successful physical light pulse was established. Independent readback confirmed the original lighting settings were retained.

The same camera advertised no ONVIF relay outputs. Its built-in siren has no verified local command in this implementation. These observations do not establish support on other models or through the NVR UI.

## Configure an opt-in control

Identify the actual control endpoint and lens before adding any of these blocks to a camera:

```json
{
  "ptz": {"onvif_port": 80, "profile_token": "Profile000", "max_move_seconds": 2},
  "white_light": {"profile": 0, "brightness": 50},
  "alarm_output": {"onvif_port": 80, "relay_token": "RelayOutput1"}
}
```

This is a fragment, not a complete configuration. Use only supported blocks; do not assume the example profile or relay tokens exist.

| Control | Requirements |
| --- | --- |
| PTZ | `lens: ptz`, the source's ONVIF port and the intended lens's media profile token. `max_move_seconds` configures the controller's Stop watchdog; omitted or zero uses 10 seconds, with a maximum of 60. A failed Stop can leave the camera moving. |
| White light | Dahua/Imou source, verified lens, native `Lighting_V2` profile 0–7 and brightness 1–100. The camera's `source_index` selects the native lighting channel; `profile` selects a native lighting profile. |
| Alarm output | Verified lens and an advertised monostable ONVIF relay with an existing device-side delay of 0.1–5 seconds. The service does not reconfigure relay mode or invent an output. |

**An alarm-output relay is not a built-in siren.** A `lens: ptz` label alone enables no control. See [configuration](configuration.md) for the source account and other camera settings.

## Operator API

Use the configured loopback address, for example:

```text
http://127.0.0.1:19031/api/v1/cameras/camera-a-lens-1/controls
```

`GET` reports which controls are configured without contacting hardware. Send JSON with `Content-Type: application/json` to `POST` on the same path for an explicit operation:

| Command body | Result |
| --- | --- |
| `{"command":"white_light_probe"}` | Read the selected native white-light settings without changing them. |
| `{"command":"alarm_probe"}` | Check the advertised relay and its bounded device-side reset. |
| `{"command":"ptz_move","pan":0.2,"tilt":0,"zoom":0}` | Queue movement; axes are -1 to 1 and are checked against discovered capabilities. |
| `{"command":"ptz_stop"}` | Queue Stop, independently of other output operations. |
| `{"command":"white_light_pulse","duration_ms":1000}` | Pulse for 100–5000 ms, then attempt restoration of the previous white-light fields. |
| `{"command":"alarm_pulse"}` | Pulse the relay using its own advertised delay, then attempt an explicit inactive command. |

Browser-origin requests are rejected. Keep this operator API on loopback; do not publish or reverse-proxy it. The minimal image has no shell or curl. Use an appropriate local diagnostic client in the same network namespace or run a local test instance.

## Responses and recovery

| Response | Meaning |
| --- | --- |
| `202`, `move_queued` or `stop_queued` | PTZ command queued; not a hardware acknowledgement. |
| `200`, `completed` | Probe or pulse completed. Pulse requests wait through the action and cleanup. |
| `501`, `control_unavailable` | The requested control is unsupported or unavailable. |
| `409`, `source_control_busy` | Another operation owns the physical source's control slot, including another virtual lens. |
| `502`, `source_control_failed` | The operation failed; `final_state` is `unconfirmed`. Failed light restoration also reports `restoration_failed: true`. |

A lost connection or power interruption can prevent light restoration or PTZ Stop. Check the physical state after a failure. A white-light restore rereads settings and refuses to overwrite a concurrent change. A monostable relay's own timer bounds its activation even if the translator disappears.

## Recorder compatibility

Physical controls are separate from [simulated camera settings](events.md#virtual-detection-settings). The source-side ONVIF PTZ backend includes presets, but its Omada-side preset response remains unsupported pending a verified native contract.

The previous preset reply did not match the camera UI's nested structure, and recorder sessions failed during preset negotiation. The exact recorder failure trigger has not been isolated; a different guessed success shape is not a verified fix.

The last confirmed recovery runtime, 0.2.27, was stable with video after PTZ advertisements were disabled. Keep control advertisements disabled for ordinary deployments and validate opt-ins on a spare channel before daily recording. See the [recorded PTZ evidence](omada-protocol.md#84-recorder-resets-during-ptz-negotiation-2026-10-17).

[Operation and troubleshooting](operations.md) · [Documentation index](../README.md)
