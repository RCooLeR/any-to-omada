# Detection and events

The translator maps source detections to native Omada alarms. Motion and human intrusion have recorder-history evidence. Other model/event combinations still need validation, even when the adapter and alarm encoding have simulated tests.

## Alarm mapping

| Normalized source event | Omada alarm types |
| --- | --- |
| Motion | `2` |
| Human / vehicle / pet motion | `32` / `33` / `80` |
| Line crossing; human / vehicle / pet | `4`; `36` / `37` / `81` |
| Intrusion; human / vehicle / pet | `5`; `34` / `35` / `82` |
| Tamper | `3` |

Native `Intelligent` notifications are classified only through an explicit, evidence-based device/lens/discriminator mapping in `sources[].event_mappings`. These mappings apply to DVRIP sources. Do not reuse one model's numeric code mapping for another.

Explicit IVS classes are preserved; unclassified IVS stays ordinary line crossing or intrusion. Mixed classes become separate alarms. Unknown or conflicting source tokens stay unrouted, and unknown event families stay in the journal.

The translator cannot create detections the source does not provide. For example, native Imou human notifications have been observed while that device's ONVIF interface emitted ordinary motion only. Choose an appropriate [source adapter](configuration.md#source-adapters) and verify each lens's event index independently of its RTSP channel number.

## Event intervals

Start/Stop use wire states `1`/`3`. Pulses create a one-second interval. Rule/source keys preserve overlapping intervals and sparse stops; ambiguous stops are journaled instead of closing unrelated events.

| Condition | Behavior |
| --- | --- |
| Source disconnect | Schedules closure of open translated intervals. |
| Callback replacement | Discards pending events without replay. |
| DVRIP start with no matching stop | Can remain open until the source disconnects. |
| ONVIF interval | Expires after five minutes. |
| ISAPI alert | Ends on an inactive notification or five quiet seconds. |
| Intrusion marker | Has a separate ten-minute stale limit. |

The [event journal](operations.md#event-journal) records notifications and normalized edges for diagnostics. It is not a durable delivery outbox.

## Virtual detection settings

Virtual motion, tamper, intrusion, line-crossing and smart-frame settings filter translated events without reconfiguring physical detection rules. Simulated time, anti-flicker and sensor-rate values likewise leave the host clock, exposure and encoded picture unchanged. These values reset on translator restart.

When enabled, [in-stream markers](configuration.md#recorder-compatibility) carry observed intrusion metadata. They do not add fabricated target boxes, and line-specific marker metadata remains unimplemented.

## Verify recorder history

For each intended model/lens/event combination, trigger a known detection and check the recorder's event search. Treat source receipt, transport write, callback acknowledgement and searchable recorder history as separate stages.

`events_written` counts transport writes. `/readyz` and `native_omada_ready` report callback transport state. None establishes that the recorder stored a detection. See [status fields](operations.md#health-and-status) and the evidence-labelled [protocol reference](omada-protocol.md) when investigating a missing event.

[Configuration](configuration.md) · [Documentation index](../README.md)
