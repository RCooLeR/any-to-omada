# Physical controls

Version 0.4.1 provides opt-in recorder pan/tilt, manual sound/light alarms, and source-backed illumination settings. Each virtual camera must be mapped to the correct physical lens. A model name or a generic ONVIF PTZ node does not prove that a camera has a motor, lamp, or siren. Introduce new controls on one camera and verify recorder stability before extending the configuration.

## Configure supported hardware

Add only the blocks supported by the selected source. These are fragments, not complete configurations:

```json
{
  "ptz": {"onvif_port": 80, "profile_token": "Profile000", "max_move_seconds": 2},
  "compatibility": {"ptz_module_spec_keys": ["ptz"]},
  "deterrence": {"sound_alarm": true, "light_alarm": true, "max_alarm_seconds": 2},
  "white_light": {
    "profile": 0,
    "brightness": 50,
    "recorder_modes": ["white_led_always_on", "auto_color", "auto_ir", "ir_always_on"]
  }
}
```

| Control | Requirements and behavior |
| --- | --- |
| PTZ | Verified `lens: ptz`, the correct ONVIF media profile, and a bounded Stop watchdog. An omitted backend selects ONVIF. Native recorder capability advertises continuous pan/tilt only. |
| Native Dahua/Imou PTZ | Use `"ptz":{"backend":"dvrip","max_move_seconds":2}` without ONVIF port/profile fields. The adapter uses `source_index` and requires affirmative native pan/tilt capabilities. It does not support zoom or presets. |
| Sound/light alarm | Dahua/Imou `CoaxialControlIO` must explicitly advertise each selected output. `max_alarm_seconds` is required and limited to 1–5 seconds. Start waits for source acceptance, and the service owns an automatic Stop. Alarm light may flash; it is separate from steady illumination. |
| Illumination | A Dahua/Imou source must advertise the selected lamp modes, an actual adjustable white-light bank, and a fixed active profile matching `profile`. `recorder_modes` opts into persistent source settings. An empty list retains loopback testing only. Scheduled source profiles are rejected. |
| External relay | Optional `"alarm_output":{"onvif_port":80,"relay_token":"RelayOutput1"}` requires a real advertised monostable relay and its existing 0.1–5 second device timer. A relay is not a built-in siren. |

ONVIF `max_move_seconds` defaults to 10; native DVRIP defaults to 2. Both accept at most 60 seconds. Use a short value during initial testing. All physical blocks are absent from [config.example.json](../config.example.json).

## Recorder controls

Native `ptz.continuous_move` and `ptz.stop` reach the selected physical backend. Successful PTZ replies mean the command was queued. The watchdog attempts Stop if the recorder does not send it. Native preset-list requests remain unsupported: the earlier fabricated response correlated with recorder system errors. Zoom, presets, tours, absolute movement and relative movement are not advertised.

Manual alarms use `do msg_alarm.manual_msg_alarm` with `action: start` or `stop`. The start reply includes a numeric `timer` only after the source accepts the command. The Stop deadline starts when activation is attempted; a delayed acknowledgement does not extend it. `msg_alarm.chn1_msg_alarm_info` selects the enabled sound/light outputs for this manual action. Automatic event arming, schedules, custom recordings, repeat counts, siren volume and flash-frequency changes are not implemented and are rejected. Unsupported donor alarm advertisements are removed only on cameras with explicitly configured outputs; cameras without those controls retain their enrollment compatibility profile.

Persistent illumination uses the recorder's image/night-vision settings, rather than a temporary alarm-light pulse:

| Native policy | Physical source policy |
| --- | --- |
| `white_led_always_on` | White-light scheme, manual lamp mode |
| `auto_color` | White-light scheme, automatic lamp mode |
| `auto_ir` | Infrared scheme, automatic lamp mode |
| `ir_always_on` | Infrared scheme, manual lamp mode |

The `image.common.smartwtl` and `smartwtl_digital_level` settings select automatic/manual white intensity and a 0–100 percentage. Brightness changes preserve the current illumination scheme. Successful writes require source readback; failed partial writes attempt to restore only fields still owned by the request. These are intentional persistent configuration changes and survive translator restart.

Passive recorder reads use a validated source snapshot refreshed in the background every 10 seconds. They never wait for source I/O. Physical settings are omitted before the first successful refresh, after a failed refresh, or once the snapshot is 30 seconds old. Writes invalidate the snapshot and request a fresh readback. Only explicitly configured illumination cameras advertise the implemented lamp capability sections and supported night-vision modes.

The Dahua source RPC uses the base names `Lighting_V2` and `LightingScheme` with complete device tables, matching the camera's shipped UI. Indexed config names are not scalar selectors on the verified firmware. Before each write or restoration, the adapter reads a fresh table, checks the selected fields, and changes only the requested channel/profile values while retaining the other settings. It never replays an old whole-device snapshot. Source operations are serialized within the translator; a separate camera client can still race the device's read/write interface.

An existing source smart-light policy without a verified native equivalent is omitted from the native mode readback. It is never reported as OFF. The recorder has some fixed menu choices; unsupported choices, including unimplemented smart-trigger/off policies, are rejected even if its UI displays them. Full recorder-page rendering and forwarding require testing with the actual recorder firmware.

## Operator API

Health/status and explicit tests use the configured loopback listener, for example:

```text
http://127.0.0.1:19031/api/v1/cameras/camera-a-lens-1/controls
```

`GET` reports configured controls without contacting hardware. `POST` requires JSON and `Content-Type: application/json`:

| Command body | Result |
| --- | --- |
| `{"command":"ptz_move","pan":0.2,"tilt":0,"zoom":0}` | Queue supported normalized movement; axes are -1 to 1. |
| `{"command":"ptz_stop"}` | Queue priority Stop. |
| `{"command":"sound_alarm_start"}` | Start the configured sound alarm for its bounded duration. |
| `{"command":"light_alarm_start"}` | Start the configured alarm light. |
| `{"command":"deterrence_start"}` | Start all configured sound/light alarm outputs. |
| `{"command":"deterrence_stop"}` | Stop owned alarm outputs, independently of the source admission gate. |
| `{"command":"white_light_probe"}` | Validate the source illumination contract when `recorder_modes` is configured; otherwise read the legacy experimental lighting configuration. |
| `{"command":"white_light_pulse","duration_ms":1000}` | Apply a temporary manual white setting and restore it when `recorder_modes` is configured; otherwise use the legacy experimental pulse. |
| `{"command":"alarm_probe"}` | Check the configured external relay and its device-side timer. |
| `{"command":"alarm_pulse"}` | Activate that relay once, then attempt an explicit inactive command. |

Browser-origin requests are rejected. Keep this API on loopback. The container image has no shell or curl; use an appropriate local diagnostic client rather than exposing the endpoint.

## Outcomes and recovery

PTZ replies report queued work. Alarm starts report `source_acknowledged` and their timer; this does not measure the physical light or sound. Unsupported controls return `501`; concurrent source operations return `409`; failed writes return `502` with `final_state: unconfirmed`. Failed alarm cleanup adds `stop_unconfirmed`, and failed light restoration adds `restoration_failed`.

`/status` retains uncertain PTZ motion, alarm state and persistent illumination restoration failures. A failed Stop or a lost connection can leave an output active. Local watchdogs require the translator and network to remain available; they are not device-side timers. Illumination restoration preserves unrelated settings and refuses to overwrite another controller's changes. HTTP/callback shutdown waits for bounded cleanup.

## Verification limits

The native PTZ and alarm request vocabulary is supported by shipped camera UI code and TP-Link's [official camera emulator](https://emulator.tp-link.com/vigi-ipc/admin/Index.htm). Native reference reads confirm alarm-setting shapes. Software tests exercise both authenticated HTTPS and native callback paths, source failures, cancellation, watchdogs and cleanup.

One Imou camera has operator-confirmed NVR pan/tilt and direct physical sound/light activation. Other configured outputs require their own device/recorder validation; a capability flag alone is insufficient. Cameras with rejected control requests remain disabled for those controls. The source-side ONVIF backend retains preset support for explicit clients, but the recorder-native preset-list contract remains unsupported.

On a DH-T4A-PV, a temporary 20% manual white setting held for one second passed source readback, followed by successful restoration and readback of the original settings. This verifies the complete source configuration path; it does not establish recorder UI behavior on every firmware or white-light support on other camera models.

[Configuration](configuration.md) · [Operation and troubleshooting](operations.md) · [Documentation index](../README.md)
