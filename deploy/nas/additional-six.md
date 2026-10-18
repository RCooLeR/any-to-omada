# Expanding to twelve virtual cameras

Extend the [six-endpoint example](all-six.md) with six more verified lenses. This table continues its documentation-only addressing plan:

| Virtual IP | Example camera ID | Backend HTTPS / RTSP |
| --- | --- | --- |
| 198.51.100.216 | camera-7 | 18449 / 18560 |
| 198.51.100.217 | camera-8 | 18450 / 18561 |
| 198.51.100.218 | camera-9 | 18451 / 18562 |
| 198.51.100.219 | camera-10 | 18452 / 18563 |
| 198.51.100.220 | camera-11 | 18453 / 18564 |
| 198.51.100.221 | camera-12 | 18454 / 18565 |

The actual virtual addresses must be allocated outside DHCP and other static assignments. Extend the certificate IP SANs, host port publications and routing together. Changing a JSON address alone does not configure any of those layers.

For a camera reached directly, use its own media channel and native event index, not the number it had on another NVR. A channel labelled 11 on a recorder can still be physical RTSP channel 1 and event index 0. Verify its credentials, main/sub stream URLs and event adapter independently.

Dahua/Imou commonly use `/cam/realmonitor?channel=1&subtype=0` and subtype 1. Some tested Dahua models reject the optional Imou `proto=Onvif` query with a native account; preserve model-specific verified URLs. Brand names and similar enclosures do not establish identical capabilities.

Before activation, validate that the original six camera objects, credentials and port mappings remain unchanged. Add source entries only for new physical cameras; additional lenses reuse the physical source. Do not copy an `Intelligent` numeric-to-class mapping from another model without captured evidence.

Twelve virtual cameras can open 24 upstream main/sub profiles. Source event subscriptions remain one per physical source. Check network throughput, camera connection limits and host memory rather than assuming the maximum configured count is a throughput guarantee.

Activate only the translator service. Verify each new channel's main/sub video and record a known event in the NVR's own history. Review unknown journal events for that model before expanding mappings. Existing streams reconnect during the container recreation; no router reboot or whole-stack restart is inherently required.

The Mango `-additional-lan` profile owns a separate table and configuration namespace for its six extra aliases. Its fixed reference addresses differ from this example; adapt the routing and application together and follow the [same-LAN guide](../mango/README-lan-forwarding.md#six-additional-lan-vips).
