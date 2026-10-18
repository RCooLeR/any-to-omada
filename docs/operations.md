# Operation and troubleshooting

Configuration and secrets load at startup. Restart after changing them. Transient failures reconnect with bounded backoff; authentication rejection stops that event subscription's retries until restart.

## Health and status

Health, status and the [operator API](controls.md#operator-api) use the configured loopback listener. The example is `127.0.0.1:19031`.

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Process liveness. Used by the `healthcheck` command and image healthcheck. |
| `/status` | Per-source and per-camera state, callback counters and failure stage. |
| `/readyz` | HTTP 200 when at least one authenticated callback connects; otherwise 503. |

`/readyz` and `native_omada_ready` do not mean that all cameras are ready, enrollment is complete or events are recorded. Inspect the individual camera entries in `/status`.

The status fields `native_alarm_delivery: implemented_unverified` and `recorder_history_verified: false` deliberately avoid declaring recorder storage success from transport activity. `events_written` means a transport write. Callback acknowledgements and searchable recorder history are separate stages. `discovery_shape: not_applicable` is normal outside stream discovery.

Run the binary's liveness check with the same configuration as the service:

```sh
../any-to-omada-bin healthcheck --config /path/to/private/config.json
```

This checks `/healthz` only. It is not an end-to-end camera or recording check.

## Event journal

The journal retains redacted native notifications and normalized event edges. The example keeps 16 segments of 4 MiB, approximately 64 MiB, with five-second and normal-shutdown flushing. Old owned segments retire across restarts.

One writer owns the directory through an OS lock. Storage errors stop the service. The journal is diagnostic storage, not a durable delivery outbox; power loss can lose its unsynced tail. Callback replacement discards pending events without replay. See [event intervals](events.md#event-intervals) for source-specific expiry behavior.

## Diagnose a failed camera

1. Check the startup version and that the intended private configuration was loaded. Use `check` to catch invalid fields and mappings; it does not test credentials or reachability.
2. Check source RTSP readiness and the verified lens mapping. Main/sub URLs must refer to the intended physical source, and the event index must be checked separately from the RTSP channel.
3. Check the virtual IP and HTTPS/RTSP routing, including any configured transport-peer allowlist. `advertised_ip` and `recorder_ip` do not create routes or client restrictions.
4. Inspect the camera's callback state and failure stage. The tested native callback uses TCP 6000 from translator to recorder.
5. Check recorder video, then trigger a known detection and inspect recorder event search. A successful transport write or acknowledgement alone does not prove saved history.

Share startup versions and fixed-label errors when reporting failures. Exclude raw authentication payloads, tokens, passwords and private runtime configuration.

## Controls and recorder stability

The last confirmed recovery runtime, 0.2.27, was stable with video after PTZ advertisements were disabled. Earlier native preset responses were associated with recorder session failures; the exact trigger has not been isolated. Successful video does not establish control compatibility.

Keep control advertisements disabled for ordinary deployments. The [control guide](controls.md) documents opt-in testing, response meanings and recovery after an unconfirmed physical operation.

## Deployment references

Use the [NAS/container guide](../deploy/nas/README.md) for permissions and executable updates, the [six-endpoint example](../deploy/nas/all-six.md) for a larger inventory, and the [expansion guide](../deploy/nas/additional-six.md) for additional endpoints. The [Mango routing profiles](../deploy/mango/README.md) describe fixed reference topologies that need review before reuse.

Every virtual stream crosses the translator. A process or network outage interrupts those streams; there is no direct-camera failover.

[Getting started](getting-started.md) · [Documentation index](../README.md)
