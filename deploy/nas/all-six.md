# Six virtual endpoints from four physical cameras

This is a layout example, not a published device inventory. Replace the documentation-only addresses with your reserved virtual addresses. Define each physical source once in `sources`; define each independently verified lens in `cameras`.

| Virtual IP | Source | Native index | Lens label | Backend HTTPS / RTSP |
| --- | --- | --- | --- | --- |
| 198.51.100.210 | dual-a | 0 | ptz | 18443 / 18554 |
| 198.51.100.211 | single-a | 0 | channel | 18444 / 18555 |
| 198.51.100.212 | single-b | 0 | channel | 18445 / 18556 |
| 198.51.100.213 | dual-a | 1 | fixed | 18446 / 18557 |
| 198.51.100.214 | dual-b | 0 | ptz | 18447 / 18558 |
| 198.51.100.215 | dual-b | 1 | fixed | 18448 / 18559 |

These indexes are illustrative. Confirm each model's association between event source index, media profile and physical lens. A `ptz` label alone does not enable controls. Use `channel` when the media mapping is verified but the lens mechanics are not.

For a typical dual-lens Dahua/Imou device, RTSP channel 1 and channel 2 select separate lenses, with subtype 0/1 selecting main/sub. That convention must be checked on the actual camera; native event indexes are separate configuration. Unknown events must not be assigned to a convenient lens.

Every virtual endpoint has its own unique ID, virtual IP, backend listener pair and virtual account. Accounts may share a secret reference. Both entries for a dual-lens camera share the same `source_id`, but have distinct `source_index`, stream URLs and virtual identity. Confirm all mappings before setting `verified: true`.

For six endpoints:

1. Reserve six virtual IPs and include them in the HTTPS certificate's IP SANs.
2. Publish the twelve TCP backend ports on the host's intended LAN address.
3. Forward each virtual IP's 443/554 to its pair, matching the container listener ports.
4. Enable only verified sources/lenses in the private JSON and validate it.
5. Activate only the translator, then check each endpoint's main/sub video and expected events independently.

Add each endpoint to the NVR using Omada/TP-LINK, port 443, and that endpoint's configured virtual account. No NVR source-channel number is substituted into a direct-camera RTSP URL. All streams traverse the translator; a stopped or unavailable physical camera affects its own lenses and is retried with bounded backoff.

The [Mango scripts](../mango/README.md) contain a different fixed reference addressing plan. They must be reviewed and adapted consistently before use with these documentation-only addresses. See the [NAS deployment guide](README.md) for runtime files and activation.
