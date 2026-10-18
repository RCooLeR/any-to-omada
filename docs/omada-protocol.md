# Omada native camera protocol, as observed

This document collects what the project has established about the private
protocol between an Omada NVR and a native Omada camera, and what the recorder
requires before it streams a camera and stores its events. It is a
reverse-engineering record, not a vendor specification. any-to-omada uses it to
present non-Omada cameras to the recorder.

The implementation is an independent, temporary compatibility workaround while
native ONVIF interoperability improves. This document is not an official
TP-Link or ONVIF specification, certification or promise of vendor changes.
See [legal and compatibility notices](legal.md).

## 0. Scope and conventions

**Devices.** Omada NVR16-8P (declares itself `Omada NVR16-8P(UN) 1.0`) and an
Omada 8MP Turret, hardware 1.0, firmware 1.0.7 Build 260911 (the "real camera").
Other firmware versions may differ.

**Evidence.**

- Captures of the real camera being enrolled and running (2026-10-15 and
  2026-10-16) through a TLS-terminating management proxy, a recorder-side
  callback terminator and RTSP relays maintained as external research tooling
  (not included in this repository). HTTPS bodies,
  callback frames and RTSP control were decoded; one capture also kept the
  RTSP media bytes.
- Static analysis of the camera firmware (GPL sources and the unpacked root
  file system) and of the recorder's web UI scripts.
- Acceptance tests of this translator against the same recorder, read back
  through the recorder's own web API.

**Labels.** Statements carry one of: **observed** (seen on the wire),
**firmware** (read from camera code), **UI** (read from the recorder's web UI
scripts), **inferred** (consistent with the evidence but not isolated),
**unverified**. Device identifiers, credentials, nonces and tokens are never
reproduced; placeholders are written `<like this>`.

## 1. Topology

| Direction | Port | Purpose | Label |
| --- | --- | --- | --- |
| recorder в†’ camera | TCP 443 | HTTPS management API, one TCP connection per request | observed |
| recorder в†’ camera | TCP 554 | RTSP over TCP, one session each for main and sub stream | observed |
| camera в†’ recorder | TCP 6000 | native callback: PAKE, TLS, declarations, passthrough requests, heartbeats, alarms | observed |
| camera | 2020, 8800, 8443 | ONVIF, vhttpd, vhttpsd: advertised in CET and UPnP answers; the recorder opened none of them | observed |
| camera | 80, 1025 | HTTP and an unknown service; 1025 did not answer, 80 was not relayed | unverified |

The camera dials the recorder for the callback after the recorder registers it
over HTTPS. Video always flows over the recorder's own RTSP connections.

## 2. Enrollment and session lifecycle

Clean enrollment of the real camera (2026-10-16 08:43 UTC; offsets from the
first request; observed):

1. `+0.0 s` HTTPS anonymous `get_rtsp_info` (stream discovery).
2. `+0.2 s` HTTPS callback registration without a session в†’ 401 challenge;
   login; registration repeated with the session в†’ success.
3. `+1.5 s` to `+2.8 s` HTTPS reads: `function.module_spec`,
   `network.wan_status`, `video` main and minor, `device_info`,
   `upnpc.upnp_status`, `cet` rtsp and vhttpd.
4. `+2.2 s` the camera connects to recorder port 6000; PAKE and TLS complete
   at `+2.6 s`; both sides send declarations at `+2.8 s`.
5. `+2.8 s` to `+3.0 s` callback passthrough requests: time zone and DST
   (`set system`), the first of which triggers application authentication;
   `get system.time_status`; `do system.set_time`; anti-flicker and sensor
   frame rate (`set image/video`); `get device_info`.
6. `+4.2 s` the recorder opens both RTSP sessions and starts streaming.
7. From `+4.4 s` an optional settings sweep over the callback: face snapshot,
   `protocol.wan`, image settings and capability, alarm lights and sounds, AI
   enhancement, smart detection, smart analysis, linkage, smart frame
   (`marker_box`), motion, tamper, intrusion, line crossing and other detection
   modules, audio, system, OSD, privacy cover, advanced settings. The real
   camera itself answers many of these with "unsupported".

After enrollment (observed):

- About every 10 minutes the recorder repeats the core read set over the callback.
- If the callback drops, the recorder repeats discovery, registration, login
  and the read set within about 30 s.
- Once the camera has declared itself on the callback, the recorder sends the
  remaining reads there instead of over HTTPS. `function.module_spec` and
  `network.wan_status` were always read over HTTPS first.
- The recorder sends `do video.force_iframe` for main and minor right after
  PLAY and after each motion alarm start.

## 3. HTTPS management API (recorder в†’ camera, port 443)

### 3.1 Transport (observed)

- TLS 1.2, camera as server. The recorder accepted the translator's own
  certificate, so it does not pin the camera's identity.
- Requests: `POST /stok=<token>/ds HTTP/1.1`, or `POST / HTTP/1.1` for login
  and the challenge. Browser-style headers: `Connection: keep-alive`,
  `Content-Type: application/json; charset=UTF-8`,
  `Accept: application/json, text/javascript, */*; q=0.01`, `Origin`,
  `Referer`, `X-Requested-With: XMLHttpRequest`, a Chrome 57 `User-Agent`,
  `Accept-Encoding: gzip, deflate`, `Accept-Language: zh-CN,zh;q=0.8,en;q=0.6`.
  The JSON is pretty-printed with spaces, for example
  `{ "method": "do", "get_rtsp_info": { } }`.
- Responses: `HTTP/1.1 200 OK` or `401 Unauthorized`, `Connection: close`,
  `X-frame-options: SAMEORIGIN`, `Cache-Control: no-cache`,
  `Access-Control-Allow-Origin: *`, `Content-Type: application/json`,
  `Transfer-Encoding: chunked`. The camera closes every connection.

### 3.2 Envelope and error codes

A request is `{"method": "do"|"get"|"set", "<module>": {вЂ¦}}`: one module for
`do` and `set`, one or more for `get`. Every response carries an integer
`error_code`.

| Code | Meaning | Label |
| --- | --- | --- |
| `0` | success | observed |
| `-40106` | unsupported operation, module or selector; HTTP status stays 200; the camera echoes an empty module object, for example `{"face_snapshot":{},"error_code":-40106}` | observed |
| `-40401` | not authenticated; HTTP 401; `data` holds the login challenge with `code: -40407` | observed |
| `-40404` | login lockout, `sec_left` seconds (recorder's own web API) | UI |
| `-52413` | `NO_NETWORK_VIDEO`, shown by the recorder player for a channel whose `conn_status` is not `0` | UI |

### 3.3 Sessions, challenge and login

`stok` is an opaque token from login, carried in the path as
`/stok=<token>/ds`. Stream discovery also works anonymously at `/stok=/ds`.
The recorder logs in again whenever a request returns `-40401` (observed).

Challenge, requested with `{"method":"do","user_management":{"get_encrypt_info":null}}`
or returned for any unauthenticated request (observed):

```json
{"data":{"code":-40407,"encrypt_type":["1","2"],"key":"<RSA public key>","key_2":"<RSA public key>",
         "nonce":"<hex>","passwdType":"<вЂ¦>","dac":{"mac":"<camera MAC>","cn":"Omada 8MP Turret(UN)"},
         "pakeCipher":{"cipherSuites":[1],"encryptType":[1]},"secVersion":"1.0"},
 "error_code":-40401,"device_type":"SECUR.CONSUMER.IPC"}
```

Login type 1, which the recorder used with the real camera (observed):

```json
{"method":"do","login":{"username":"admin","password":"<proof>","passwdType":"md5"}}
```

`<proof>` is the uppercase hexadecimal MD5 of `TPCQ75NF2Y:` followed by the
account password (verified against three captured logins). The answer is
`{"user_group":"root","stok":"<token>","error_code":0}`. A challenge that
offers only `encrypt_type ["1"]`, `passwdType "md5"`, `nonce` and
`secVersion` is accepted (observed with the translator). Login type 2 (RSA,
`key_2`) was not needed for this recorder.

### 3.4 Stream discovery and callback registration

`{"method":"do","get_rtsp_info":{}}` в†’ `{"stream_num":0,"ip_src_num":0,"error_code":0}`.
The numbers count active RTSP sessions and distinct client addresses, not
profiles: the same camera answered `0/0` when idle and `0/1` while another
channel streamed it (observed, firmware).

Registration (observed):

```json
{"method":"do","nvr_long_connect":{"nvr_connect_start":{"ip":"<recorder IP>","port":6000,"version":"0101000101","auth_code":"<secret>"}}}
```

The answer is `{"version":"0101000101","error_code":0}`. `auth_code` is a
fresh secret per registration and serves as the PAKE password (section 4.2).
`nvr_connect_stop {"ip","port"}` ends it (translator contract, unverified).

### 3.5 Reads (`method: get`)

Each module takes a selector `{"name": "<section>" | [names], "table": "<table>" | [tables], "version": "1"}`.
Detection modules carry `version`. The answer nests module в†’ section в†’ leaves.
A requested section the camera lacks is left out without an error, for example
`video_capability.capability` (observed).

**Value types (observed).** Almost every leaf is a string, including numbers
(`"port":"554"`, `"bitrate":"8192"`), flags (`"0"`, `"1"`) and switches
(`"on"`, `"off"`). These are integers: `up_time`, `link_status`, `phy_status`,
`internet_status`, `up_speed`, `down_speed`, `pppoe_link_status`,
`time_status` seconds and microseconds, `basic_info.features`,
`info.cover_reg_num`, `md_reg_num`, `roi_reg_num`, `isp_version`,
`motion_det.digital_sensitivity` (while `tamper_det.digital_sensitivity` is a
string), region coordinates and counts. A frame rate is written as `65536 + fps`
in a string, so 25 fps is `"65561"`; the recorder UI subtracts 65536.

**String encoding (observed).** Every string in an answer is percent-encoded
with the `encodeURIComponent` alphabet and lowercase hex, for example
`"Omada%208MP%20Turret"`. The recorder stores the encoded form and its UI
decodes it. Request strings arrive unencoded over HTTPS and percent-encoded
over the callback (section 4.5).

**Core enrollment reads** (real camera, identifiers removed; observed):

- `function.module_spec`: about 150 capability leaves. Among them
  `omada_ipc "1.0"`, `nvr_long_connect "1.0"`, `video_codec ["h264","h265"]`,
  `events ["motion","tamper"]`, `smart_detection "1"`, `smart_codec`,
  `media_encrypt`, `auth_encrypt`, `digest_switch`, `marker_box "1"`,
  `marker_box_type "1001111"`, `multi_user "2"`, `pwd_rule_ver "1.1"`,
  `audio ["speaker","microphone"]`, `playback_target_types ["people","vehicle","pet"]`,
  `alg_event_property ["object_filter","object_filter_enabled"]`,
  `stream_protocol ["srtp","dash"]`, `streaming_support_versions ["1.1"]`,
  `stream_max_sessions "10"`. The recorder derives the channel capability
  bitmap of section 7.2 from this set.
- `network.wan_status`: `ipaddr`, `netmask`, `gateway`, `pri_dns`, `snd_dns`,
  `phy_status 1`, `proto "static"`, `link_status 1`, `internet_status 0`,
  `up_time`, `up_speed 0`, `down_speed 0`, `pppoe_link_status 0`,
  `pppoe_ipv4 "0.0.0.0"`, `mac` in lowercase with hyphens, `error_code 0`.
- `video` main and minor: `quality "3"`, `bitrate`, `frame_rate`,
  `encode_type` (`H265` main, `H264` minor), `resolution "3840*2160"`,
  `bitrate_type`, `name "VideoEncoder_1"` or `"VideoEncoder_2"`; main also has
  `smart_codec`, `default_bitrate`, `adaptive_mode`; minor has
  `socialshare_auto_h264 "0"`.
- `device_info.basic_info`: `device_type "SECUR.CONSUMER.IPC"`, `device_info`,
  `features 3`, `barcode`, `device_model`, `sw_version`, `device_name`,
  `hw_version "1.0"`, `device_alias`, `dev_id`, `hw_id`, `fw_cur_id`, `oem_id`,
  `region "UN"`, `imei ""`, `mac` (uppercase), `manufacturer_name "TP-LINK"`,
  `passwdType`. `device_info.info`: `device_model`, `manufacturer_name`,
  `sw_version`, `hw_version`, `model_description "IPC"`, `device_name`,
  `devcode`, `sn`, `cover_reg_num 4`, `md_reg_num 32`, `roi_reg_num 0`,
  `isp_version 1`, `isp_sw_version`, `up_time`.
- `upnpc` table `upnp_status`: five rows, `uhttpd` 443, `rtsp` 554,
  `onvif_service` 2020, `vhttpd` 8800 and `vhttpsd` 8443, each
  `{ipaddr, status "off", ext_port, inner_port}`. Name `upnpc_info`:
  `{"enabled":"off","mode":"manual"}`.
- `cet` rtsp and vhttpd: `{"port":"554","digest_auth_type":"MD5"}` and
  `{"port":"8800","digest_auth_type":"MD5"}`.
- `system.time_status`: `{"seconds_from_1970":N,"u_seconds":N}`.

**Detection and smart reads** (real camera; observed):

- `motion_detection` (version 1), names `motion_det`, `arming_schedule`,
  `motion_notif_list`, `feature`, tables `md_polygon_region_info`,
  `polygon_region_info`, `region_info`.
  - `motion_det`: `enabled`, `sensitivity "medium"`, `digital_sensitivity 50`,
    `people_enabled`, `vehicle_enabled`, `pet_enabled`, `non_vehicle_enabled`,
    `target_validity`, `obj_filter_enabled`, target size bounds (0вЂ“10000),
    `mb_enabled`.
  - `arming_schedule`: one leaf per weekday holding a JSON array of
    `HHMM-HHMM` ranges inside a string, for example `"[\"0000-2400\"]"`.
  - `motion_notif_list`: `client_enabled`, `app_enabled`, `msg_push_enabled`,
    `sound_alarm_enabled`, `light_alarm_enabled`, `record_enabled`,
    `AO1_enabled`, `ftp_enabled`, `capture_enabled`, `email_enabled`,
    `target_track_enabled`, `report_server_enabled`.
  - `feature`: `{"max_points_num":"16"}`.
  - Region rows are keyed `<table>_1`, `<table>_2`вЂ¦ and hold `points_num`,
    `points_x[]`, `points_y[]` (polygon) or `x_coor`, `y_coor`, `width`,
    `height` (rectangle) on a 0вЂ“10000 grid.
- `tamper_detection`: `tamper_det {"enabled","sensitivity","digital_sensitivity":"50"}`
  and a notify list like motion's without `target_track_enabled`.
- `intrusion_detection` (version 1): `detection {"enabled":"on"}`, a notify
  list, a schedule, a feature and region rows with `id`, `sensitivity`,
  `threshold`, `percentage`, `position_pan/tilt/zoom` (floats),
  `people_enabled`, `vehicle_enabled`, `pet_enabled`, `ebike_enabled`,
  `constant_alarm_enabled`, `non_vehicle_enabled`, `target_validity`,
  `obj_filter_enabled` and target size bounds; polygon rows also carry the
  point lists, rectangle rows `pt1_x` to `pt4_y`.
- `linecrossing_detection`: same shape with `polyline_region_info`;
  `detection` was off on the real camera.
- `marker_box.detection`: `{"enabled":"on"}`. This is the camera's smart-frame
  switch for the in-video target metadata of section 6.
- `smart_detection.capability`: one `"0"` or `"1"` per detection type:
  `linecrossing_detection`, `intrusion_detection`, `regionentrance_detection`,
  `regionexiting_detection`, `loitering_detection`, `fastmoving_detection`,
  `parking_detection`, `unattendedbaggage_detection`,
  `abandonandtaken_detection`, `objectremove_detection`, `face_detection`,
  `scenechange_detection`, `defocus_detection`, `audioabnormal_detection`,
  `overline_detection`, `vehicle_detection`, `smart_data`, `people_detection`,
  `people_detection_capability`, `peoplevisit_detection`, `pet_detection`.
  The real camera reported line crossing, intrusion and `smart_data` as `"1"`.
- `ai_enhance_capability.traditional_enhance`:
  `{"people_enhance_ver":"7","vehicle_enhance_ver":"7","pet_enhance_ver":"7"}`.
- `linkage_capability.capability`: 36-character bit strings
  `sound_alarm_capability`, `light_alarm_capability`, `record_capability`,
  `msg_push_capability`, `ftp_capability`, `email_capability`,
  `report_server_capability` (bit meanings not decoded).
- Several modules answer `-40106` even on the real camera: `face_snapshot`,
  `smart_analysis`, `sound_detection`, `alarm_input`, feature-only selectors of
  some detections.

### 3.6 Writes (`set`, `do`)

Observed from the recorder, mostly over the callback; the real camera answers
`{"error_code":0}`:

- `set system`: `basic {"timezone":"UTC+02:00","zone_id":"Europe/Vilnius","date_format":1,"time_format":0}`
  and `dst_manual {"enabled":"on","dst_savings":60,"start_month":3,"start_week":5,"start_day":0,"start_hour":3,"end_month":10,"end_week":5,"end_day":0,"end_hour":4}`.
- `do system.set_time`: `source_time_priority "NVR_NTP"`, `source_mac`,
  `transmit 0`, `T1_timestramp` to `T3_timestramp` with microsecond companions
  (the firmware spells "timestramp"). The camera corrects its clock by
  `(T2 + T3 в€’ T1 в€’ T4) / 2`, where T4 is its own receive time (firmware).
- `set` anti-flicker and sensor rate together:
  `{"image":{"switch":{"flicker":"50hz"}},"video":{"common":{"sensor_framerate":"25"}}}`
  (`60hz` and `30` are the alternatives), before the first RTSP connection.
- `do video.force_iframe {"stream_type":"main"|"minor"}` after PLAY and after
  each motion alarm start.
- `set protocol.wan` (static), `do system.nvr_upgrade {"is_upgrade":0}`.
- Detection settings pushed from the recorder's own configuration:
  `set intrusion_detection` `notify_list`, `arming_schedule`, `detection`;
  `do intrusion_detection.add_polygon_regions {"polygon_region_info":[{"id":1,"points_x":[вЂ¦],"points_y":[вЂ¦],"points_num":"4",вЂ¦,"people_enabled":"on",вЂ¦}]}`;
  `set tamper_detection.tamper_det`. Numeric leaves arrive as strings in writes.
- `set marker_box.detection {"enabled":вЂ¦}` when the operator toggles smart frame.

## 4. Native callback (camera в†’ recorder, port 6000)

### 4.1 Pre-TLS framing (observed, firmware)

```
--start-boundary--\r\n
Content-Type:ALG_Ver\r\n
Content-Length:<n>\r\n
{"step":<k>,"data":"<base64>","error_code":0}\r\n
--end-boundary--\r\n
```

The camera writes headers without a space after the colon and orders the keys
`step, data, error_code`. The recorder writes `Content-Length: <n>` with a
space. Frames stay under 64 KiB; up to four leading CRLF pairs are tolerated.

### 4.2 Handshake (observed, firmware)

| Step | Direction | Content-Type | Payload before base64 |
| --- | --- | --- | --- |
| 1 | recorder в†’ camera | `ALG_Ver` | version offer, 1вЂ“64 bytes; the camera ignores its value |
| 2 | camera в†’ recorder | `ALG_Ver` | `1.0` |
| 3 | recorder в†’ camera | `Spake2` | 36 bytes of PAKE public data |
| 4 | camera в†’ recorder | `Spake2` | 32-byte client share |
| 5 | recorder в†’ camera | `Spake2` | 64-byte server proof |
| 6 | camera в†’ recorder | `Spake2` | 32-byte client confirmation |
| 7 | recorder в†’ camera | `Spake2` | the recorder's certificate chain (в‰¤ 10 KiB), AES-encrypted with the PAKE session keys |

The PAKE is SPAKE2+ Elligator Edition as in libsodium's `crypto_spake`, with
the registration `auth_code` as password and the identities `VIGI-IPC`
(camera, client) and `VIGI-NVR` (recorder, server); verified by interoperating
with the recorder. The camera then starts TLS 1.2 as client and trusts the
chain from step 7.

### 4.3 Post-TLS framing and identifiers (observed, firmware)

```
--start-boundary--\r\nContent-Type:<type>\r\nContent-Length:<n>\r\n<json>\r\n--end-boundary--
```

Camera frames have no space after the colons and no CRLF after the end
boundary; recorder frames write `Content-Length: <n>`. Content types are
`Declaration`, `Request`, `Response`, `Auth` and `Nofity_Event` (the firmware's
own spelling for alarms). The camera's output buffer is 1024 bytes and its
passthrough answer buffer 20 KiB.

The camera numbers its messages from 32768, wrapping from 65535 back to 32768;
the recorder numbers from 0. A `Response` repeats the request `id`, has no
`method` and carries an outer `error_code`.

### 4.4 Declarations and application authentication (observed, firmware)

Camera, first frame after TLS:

```json
{"id":32768,"method":"declaration","requestData":{"ip":"<camera IP>","mac":"AA-BB-CC-DD-EE-FF","dev_name":"<alias>","remote_flag":0,"msg_version":1,"version":"0101000101"}}
```

Recorder:

```json
{"id":0,"method":"declaration","requestData":{"ip":"<recorder IP>","mac":"<recorder MAC>","dev_name":"Omada NVR16-8P(UN) 1.0","msg_version":1,"version":"0101000101","is_full":"0"}}
```

The camera answers the recorder's first `Request` with an account challenge:

```json
{"responseData":{"time":5,"max_time":5,"realm":"vigi","algorithm":"digestmd5","qop":"auth","nonce":"<hex>","nc":"1","uri":"tplink"},"id":1,"error_code":-40401}
```

The recorder replies with an `Auth` frame holding `algorithm "digestmd5"`,
`cnonce`, `max_time`, `nc`, `nonce`, `qop "auth"`, `realm "vigi"`, `response`,
`time`, `uri "tplink"`, `username`, then repeats its request. The camera
confirms with `{"id":вЂ¦,"error_code":0,"responseData":{"username","realm":"vigi","uri":"tplink","respauth","qop":"auth","nc","cnonce"}}`.

`HA1 = MD5(username ":vigi:" T(password))`, where T is the firmware's legacy
XOR lookup transform of the password (different from the HTTPS login proof).
`response = MD5(HA1 ":" nonce ":" nc ":" nonce ":auth:" MD5("digestmd5:tplink"))`
with the server nonce in both nonce positions; `respauth` uses the client nonce
in both. `time` and `max_time` count remaining attempts, not seconds.

### 4.5 Passthrough (observed, firmware)

The recorder sends management requests (section 3) as
`{"id":N,"method":"passthrough","requestData":{<request>}}` with every string
leaf percent-encoded. The camera decodes string leaves recursively
(`requestData` must be an object), dispatches the request and answers:

```json
{"responseData":{<management answer with its own error_code>},"id":N,"error_code":0}
```

The outer `error_code` is 0 whenever dispatch happened, even when the inner
answer is `-40106`. The key order is `responseData, id, error_code`, and string
leaves in `responseData` are percent-encoded.

### 4.6 Heartbeat (observed)

The camera sends `{"id":<n>,"method":"heartbeat"}` every 10 s; the recorder
echoes `{"id": <n>, "method":"heartbeat"}`.

### 4.7 Alarms (observed, firmware)

```json
{"id":N,"method":"notify","requestData":{"notify_event":[{"event_type":34,"event_status":1}]}}
```

`event_status` is 1 at start and 3 at stop; the firmware maps its internal
states 1 and 3 to 1, 4 and 5 to 2, and 0 to 3. An optional `region_id` names
a detection region. The recorder answers
`{"id":N,"error_code":0,"responseData":{"notify_event":{"error_code":0}}}`.

Event types from the firmware's event table (2, 32 and 34 seen on the wire
from the real camera):

| Type | Label | Type | Label |
| --- | --- | --- | --- |
| 2 | motion | 34 | human intrusion |
| 4 | line crossing | 35 | vehicle intrusion |
| 5 | intrusion | 36 | human line crossing |
| 26 | human | 37 | vehicle line crossing |
| 27 | vehicle | 75 | pet |
| 32 | human motion | 80 | pet motion |
| 33 | vehicle motion | 81 | pet line crossing |
|  |  | 82 | pet intrusion |

The real camera also sends type 65535 with a 39-character bit string:

```json
{"id":N,"method":"notify","requestData":{"notify_event":[{"event_type":65535,"event_param":"000000010000000000000000000000000000000"}]}}
```

Position 7 (from 0) was set right after connecting and in a copy sent every
10 minutes regardless of activity; position 28 was set once, 16 s after
enrollment. Its meaning is unknown, and the recorder stored the camera's human
intrusions without it, so it is not needed per alarm (observed).

With motion detection disabled, the real camera still sends motion (2) and
human-motion (32) stops but never their starts. Human intrusion (34) comes as a
start and stop pair (observed over three hours).

## 5. RTSP media (recorder в†’ camera, port 554)

- Paths `rtsp://<camera>:554/stream1` (main) and `/stream2` (sub); user agent
  `TP RTSP Client`. Per stream: `OPTIONS`, `DESCRIBE` (401, then with Digest
  MD5), one `SETUP` per track, `PLAY` (observed).
- The DESCRIBE answer sets `Content-Base: rtsp://<camera IP>:554/streamN/`
  with a trailing slash. Its SDP has video (payload 96; H.265 main and H.264
  sub on the real camera), audio (payload 8, PCMA 8 kHz) and, on the real
  camera's main stream, a third track the recorder set up as
  `interleaved=240-241` with `encrypt=1` (observed).
- SETUP sends the header `Smart-Encoder:VirtualIFrame=1` (no space) on the
  first track and always
  `Transport: RTP/AVP/TCP;unicast;interleaved=0-1;encrypt=1;encryptVersion=1;keyVersion=1;smart_pkg_ver=2`
  (channels `2-3` for audio, `240-241` for the third track). The camera
  answers video and audio with
  `вЂ¦;salt=<вЂ¦>;client_ssrc=<n>;encrypt=0;encryptVersion=1;keyVersion=1`, which
  selects unencrypted RTP, and the third track with `encrypt=1` (observed).
- PLAY targets the Content-Base URL (`вЂ¦/streamN/`) with `Range: npt=0.000-`,
  `Session` and `Authorization`. The Digest `uri` names the stream URL
  without the trailing slash, so a server that insists on the exact request
  URL rejects the PLAY with 401 and the recorder retries every 6 s (observed
  with the translator).
- The recorder sends `OPTIONS` on each session every 30 s as a keep-alive.

## 6. In-video TP-Link marker metadata

Every access unit of both streams of the real camera carries one metadata
unit: 23,224 in 15 minutes on the H.265 main stream and 23,225 on the H.264 sub
stream (observed, 2026-10-15 capture, decoded 2026-10-16).

**Placement.** The unit travels in its own single-NAL-unit RTP packet after
the frame's last slice, with the frame's timestamp, and carries the RTP marker
bit (the slices before it have the marker bit clear). H.265 uses a suffix SEI,
NAL header `50 01` (type 40, temporal id 0); H.264 uses an SEI, NAL header `06`.

**SEI message.** Payload type `05` (user data unregistered), a one-byte size,
the payload, and the trailing byte `80`. Emulation prevention applies as usual.

**Payload.**

```
"TPLINKMARKERBOX."   16-byte identifier (ASCII)
01                   version
<boxes>              number of box records
<items>              number of items (the three 11-records count as one)
10                   constant
<records>            9 bytes each
00                   trailer
```

An idle frame is `TPLINKMARKERBOX.` `01 00 00 10` `00`: 21 bytes, a 26-byte
H.265 NAL or a 25-byte H.264 NAL (91 % of frames in the capture).

| Record | Layout | Meaning |
| --- | --- | --- |
| `01` | x1 y1 x2 y2, big-endian 16-bit, 0вЂ“10000 grid | motion box |
| `04` | same | human box |
| `e0` | `f1 01 f1 01 f0 00 f0 00` | rule alert: intrusion target active (bitmap 1), intrusion region active (bitmap 1), line-crossing target and region inactive; parsed this way by the vendor web player |
| `07` | `0a 02 01 01 09 00 ff ff` | always next to a rule alert; fields not decoded |
| `11` | three records `11 04 вЂ¦`, `11 08 вЂ¦`, `11 1c вЂ¦` | sent about every 2 s; probably the rule region outline for the player |

Example alert frame: header `01 02 04 10`, then a human box
`04 0919 1147 0f17 2710`, a motion box, the `e0` alert and the `07` record.
The recorder's player draws these boxes. Whether the recorder also uses the
units when it stores events is not known (section 8.3).

## 7. Recorder web API (read-only probes)

### 7.1 Login and channels

- Challenge and login at `https://<recorder>/` with headers
  `X-Requested-With: XMLHttpRequest` and `SourceType: vigi_web`. The challenge
  offers `encrypt_type "2"` with RSA keys (double percent-encoded) and a
  nonce. Login:
  `{"method":"do","login":{"encrypt_type":"2","passwdType":"sha256","password":"<base64 RSA-PKCS#1(SHA256(password) ":" nonce)>","username":"admin","keyType":"1"}}`
  в†’ `stok`. Logout: `{"method":"do","system":{"logout":"null"}}`.
- Channels: `{"method":"get","chm":{"table":["added_dev"]}}` в†’ rows keyed by
  channel id with `id`, `ip`, `port`, `online "0"/"1"`, `conn_status` (`"0"`
  streaming; `"1"` and `"2"` seen while no streams could start), `auth_result`,
  `stream_list` (`["main","minor"]` once streams exist), `connect_prot`
  (`"TP-LINK"` native, `"ONVIF"`), `vender "1"` for native cameras,
  `capability`, `model`, `firmware_version`, `hardware_version`, `sn`, `mac`,
  `multi_user`, `pwd_rule_ver`, `passwd_strength`, `phy_port` (`0` native,
  `-1` ONVIF) and others. Strings are stored percent-encoded as the camera sent them.

### 7.2 Channel capability bitmap (UI)

A 70-character `0/1` string, 1-based: display 1, stream 2, osd 3, cover 4,
roi 5, motion_detection 6, tamper 7, ptz 8, audio 9, ptz_patrol 10, ptz_3D 11,
wide_dynamic 12, auto_reboot 13, mirror 14, rotate 15, motor 16, lens_mask 17,
ptz_reset 18, sound_target_track 19, target_track 20, ptz_preset 21,
wifi_cascade_connection 22, smart_code 23, wifi 24, smart_detection 25,
image_capability 26, park_support 27, smart_enhance 28, is_fisheyes_ipc 29,
force_I_frame_support 30, audio_output 31, flicker 32, infrared_expose 33,
smart_ir 34, IR_LED_PWN 35, marker_box 36, motion_detection_poly 37,
line_cross_poly 38, object_filter 39, people_human_confidence 40,
motion_detection_schedule 41, smart_frame_separate 42, blc 44,
multi_lan_flag 45, privacy_mosaic 47, zoom_ptz 48, smart_analysis 49,
active_defense 51, usr_def_audio 52, detection_polygon_enable 53,
audio_light_union 54, support_extra_light 55, fisheye_lens_correction 56,
support_extra_sound 57, splicing 60, manual_calibration 61, anr 62,
marker_box_type 63, plan_supported 64, privacy_poly_support 66,
privacy_min_zoom_support 67, event_area_3d_support 68, qd_zero_filter 69,
omada_ipc 70.

The recorder derives the string from `function.module_spec`: the virtual
camera received the real camera's exact string once it returned the same set
(observed). The UI shows a settings panel only while the channel is online and
the panel's bit is set (UI).

### 7.3 Per-channel detection settings (UI, observed)

The recorder keeps its own per-channel copy, with 1-based channel numbers:

- `{"method":"get","intrusion_detection":{"name":["chn<N>_detection","chn<N>_notif_list"]}}`
  в†’ `{"enabled":"on","support_filter_enabled":"1"}` and a recorder-side
  notification list (`screenwarn_enabled`, `screenshot_enabled`,
  `nvr_msg_push_enabled`, `buzzer_enabled`, `popupwin_enabled`, `record_union`
  and other linkage arrays as percent-encoded JSON strings).
- `name "chn<N>_alarm_setting"` в†’ the weekly schedule; `name "chn<N>_feature"`.
- Regions: `{"method":"do","intrusion_detection":{"chn_get_id_polygon_regions":{"channel":N}}}`
  and `chn_get_id_regions`. Short names used by the UI: `md` motion,
  `id` intrusion, `ld` line crossing, `pd` people, `vd` vehicle, `pt` pet,
  `regen` region entrance, `regex` region exit, `at` abandoned/taken,
  `lt` loitering, `sc` scene change, `ae` audio exception, `sd` sound, `qu` queue.
- Motion uses `chn<N>_motion_det`, `chn<N>_motion_notif_list` and
  `chn<N>_alarm_setting`; tamper uses `chn<N>_tamper_det` and
  `chn<N>_tamper_notif_list`. `_nvr` module variants exist for detection done
  by the recorder itself.
- `{"method":"do","chm":{"chm_get_all_channel_smart_detection":{"channel":"all","event_type":"intrusion_detection"}}}`
  в†’ `{"enabled":"1001000вЂ¦"}`, one character per channel; the UI shows a smart
  event page for a channel only when its character is `1`.

The recorder takes these values from the camera: after the virtual camera
reported motion detection off, the recorder's `chn<N>_motion_det` also said
off. It pushes its stored intrusion settings to a camera during enrollment.

### 7.4 Event history

`{"method":"do","system":{"get_user_id":null}}` в†’ `user_id`, then:

```json
{"method":"do","playback":{"search_video_event_playback":{"client_id":<user_id>,"search_id":<random>,
  "event_type_low32":<mask>,"event_type_high32":<mask>,"channel_map":[<0-based channel>],
  "start_time":<epoch>,"end_time":<epoch>,"start_index":0,"end_index":99}}}
```

в†’ `playback.search_video_results`, rows `{channel, eventType, startTime, endTime}`
as strings. Bit n of `event_type_low32` selects history type n. History types
differ from camera alarm types: 1 motion, 5 human motion, 7 human intrusion,
8 vehicle motion, 37 pet motion. Intervals include roughly 4 s of pre-recording
and 2 s of post-recording (observed).

## 8. What the recorder requires

These findings come from presenting virtual cameras to the recorder on
2026-10-16 and reading the results back through section 7.

### 8.1 Streaming

1. Type-1 login, `/stok=` sessions and anonymous stream discovery.
2. Callback registration answered, PAKE and TLS completed, declaration sent,
   application authentication answered, heartbeats running.
3. The core reads of section 3.5 answered with the real camera's shapes,
   including encoder `name` and `quality`, the UPnP service rows,
   `link_status` and `phy_status`, `nvr_long_connect "1.0"`, and the time and
   anti-flicker writes acknowledged.
4. With a minimal capability set the recorder completed every step but never
   listed streams (`stream_list []`, `conn_status` 1 or 2) and never opened
   RTSP. Returning the real camera's full `module_spec`, the vhttpd entries in
   CET and UPnP, the optional encoder leaves, `hw_version`, `sn` and counts in
   `device_info`, netmask, gateway and DNS in `wan_status`, and percent-encoded
   HTTPS strings together made it list both streams and open RTSP within 3 s.
   Which of these it needs has not been isolated.
5. RTSP Digest verification must accept a PLAY `uri` without the trailing slash.

### 8.2 Motion events

Motion alarms are acknowledged in every case but appear in the history only
after the camera answers `motion_detection`, `tamper_detection`,
`intrusion_detection` and `smart_detection.capability` like the real camera.

### 8.3 Human events

The recorder stores a human intrusion (alarm 34) as history type 7. For the
virtual camera this happened only after a series of additions:

| Translator build | Change | Human intrusion stored |
| --- | --- | --- |
| 0.2.13 | virtual motion and tamper detection; human mapped to 32 | no (motion yes) |
| 0.2.14 | people-only intrusion detection; human mapped to 34; smart detection capability | no |
| 0.2.15 | alarm starts gated by the virtual settings, motion off by default | no |
| 0.2.16 | motion on by default again | no |
| 0.2.17 | per-frame marker units with the intrusion alert (no box) | no |
| 0.2.18 | `marker_box` (smart frame) readable and writable | no |
| 0.2.19 | `ai_enhance_capability`, `linkage_capability` and `smart_data "1"` answered like the real camera | **yes** |

Ruled out as sufficient on their own: the recorder's per-channel intrusion
settings, schedules and regions (identical to the real camera's channel before
the change), keeping human intrusion apart from motion, the type-65535 bitmap,
marker units without a box, and the smart-frame switch. Which items of the
final combination are necessary has not been isolated.

### 8.4 Recorder resets during PTZ negotiation, 2026-10-17

**Observed:** the operator reported repeated NVR resets and confirmed that the
recorder became stable after stopping `any-to-omada`. The supplied translator
excerpt has no startup version, so the failing executable version is unknown.
At 09:00:20 UTC (12:00:20 Kyiv), four callback connections closed within 34 ms
at an empty frame boundary. All eight downstream RTSP connections then closed
about a second later. The translator continued retries and accepted fresh
recorder logins at 09:00:33вЂ“34 UTC; this is not a translator restart in the log.

The recorder had just requested `preset.get_preset` with `count`,
`position_info` and `start_id`. Two source reads were refused; the other
returned an empty successful list 42 ms before the shared callback loss.
**Inferred:** PTZ negotiation is a concrete isolation candidate. This timing
does not prove which response triggered a recorder process or device reset.

**UI evidence:** saved camera UI code reads nested `preset.preset.id` and
`preset.preset.name` arrays, plus an `index` array for index addressing. The
translator's earlier top-level `preset` array does not match that structure.
Release 0.2.27 rejects native
`preset.get_preset` with `-40106` without calling ONVIF; it does not replace the
reply with another guessed schema. The operator subsequently confirmed that
0.2.27 was stable with video when PTZ blocks and their module advertisement
keys were removed. This establishes the recovery configuration, not the exact
faulting response or successful PTZ interoperability. This recovery alone did not verify PTZ interoperability; do not restore the former preset
advertisements or success response based on it.

The 0.3.1 pan/tilt-only trial separates native `get ptz.capability` from the
recorder UI API. The native response includes `continuous_move_supported`
from source discovery and disables preset, zoom, absolute and relative move
advertisements. Field names, string types and native movement/Stop request
shapes are supported by TP-Link's [official camera emulator](https://emulator.tp-link.com/vigi-ipc/admin/Index.htm)
and shipped camera UI. The emulator supplies static fixtures, not captured
hardware responses. A read-only request forwarded through the NVR to a real
fixed Omada camera returned `-40106` for both native preset query forms;
the translator retains that rejection. The operator subsequently reported the
0.3.1 NVR pan/tilt trial working on one Imou lens. That is initial interoperability
evidence, not extended stability or support on every camera. Position ranges,
status and successful native preset replies remain unimplemented rather than inferred.

## 9. How any-to-omada implements it

| Area | Code | Notes |
| --- | --- | --- |
| HTTPS management API | `internal/omadafront` | login proof, sessions, discovery, registration, reads and writes; the same handler serves passthrough |
| Callback handshake and framing | `internal/omadalink`, `internal/spakeee` | PAKE, certificate delivery, TLS, declarations, application authentication, passthrough encoding, alarms |
| Virtual settings | `internal/omadafront/virtual_time.go`, `virtual_imaging.go`, `virtual_detection.go` | time zone, DST and clock offset; anti-flicker and sensor rate; motion, tamper, intrusion and smart frame. Kept in memory per camera; never written to the source camera |
| Alarm mapping | `internal/app/event_translation.go` | motion в†’ 2; smart human/vehicle/pet motion в†’ 32/33/80; line в†’ 4/36/37/81; intrusion в†’ 5/34/35/82; tamper в†’ 3; scoped `Intelligent` classes в†’ intrusion. Starts are gated by virtual settings; matching stops remain eligible |
| RTSP | `internal/camerartsp` | forwards encoded video without transcoding; own Digest MD5 verification; optional marker injection adjusts RTP sequencing |
| Marker metadata | `internal/tpmarker`, `internal/camerartsp/marker_inserter.go` | idle unit every frame; intrusion alert while a classified intrusion is open; no boxes |
| Source events | `internal/dvripcapture`, `internal/isapievents`, `internal/onvifevents` | Dahua/Imou DVRIP, Hikvision ISAPI alert stream, ONVIF PullPoint; all emit brand-neutral `VideoMotion`, `SmartMotionHuman/Vehicle/Pet`, `CrossLineDetection`, `CrossRegionDetection`, `VideoBlind` edges (`internal/cameraevents/canonical.go`) |
| PTZ | `internal/onvifptz`, `internal/dvripptz`, `internal/omadafront/ptz.go` | explicit ONVIF or native DVRIP backend with bounded continuous pan/tilt. One Imou lens has operator-confirmed NVR success. Native presets remain unsupported; see section 8.4 |
| Manual outputs | `internal/omadafront/outputs.go`, `internal/dvripcapture/deterrence.go` | source-acknowledged native manual sound/light alarms with independent Stop watchdogs; no automatic arming, custom sound or alarm schedules |
| Illumination | `internal/omadafront/illumination.go`, `internal/app/illumination.go`, `internal/dvripcapture/lighting_mode.go` | opt-in persistent source night-mode/white-brightness settings with capability checks, readback and failed-write restoration |
| Local output tests | `internal/app/controls.go`, `internal/onvifoutput` | loopback tests remain separate from recorder UI validation; an external relay is not a built-in siren |

**Validation boundary.** The ISAPI and ONVIF event adapters have
been exercised with protocol fakes only. The real-camera/recorder evidence in
this document is from Omada and translated Dahua/Imou sources; it does not
establish enrollment or event-history acceptance for other brands. Adapter
selection follows the configured source brand. Source-control backend tests
and local control endpoints do not establish that the NVR's native control
requests have the same contract.

Canonical edges preserve protocol/event provenance, known source indexes,
rules and object classes. ISAPI/ONVIF source timestamps remain in native
notification journal records, while their canonical edges use translator
receipt time. DVRIP normalization also retains its native timestamp fields.
No source timestamp or physical rule ID is invented as an Omada region ID or
target box. Pet motion type 80 is implemented; live recorder-history acceptance
for that event and the new adapters remains unverified.

The recorder-compatibility experiments are per-camera `compatibility` options,
all off by default: `module_spec_profile` (`minimal` or `omada-ipc-observed`;
the observed profile also answers `ai_enhance_capability`,
`linkage_capability` and `smart_data`), `advertise_vhttpd`,
`extended_video_fields`, `extended_identity`, `manufacturer_name`,
`encode_http_strings`, `network` and `in_stream_markers`. The virtual camera
keeps identifying itself as AnyToOmada and never copies another device's
serial, IDs or MAC.

## 10. Open questions

- Which items of sections 8.1 and 8.3 the recorder actually needs.
- Whether the recorder ever contacts ports 80, 2020, 8443 or 8800 of a camera.
- Meaning of alarm types 26, 27, 75 and 65533, of the 65535 bit positions, of
  the `07` and `11` marker records and of the linkage bit strings.
- `conn_status` values other than 0 and the contents of `rtsp_prot`.
- Type-2 (RSA) camera login and the `dac` and `pakeCipher` challenge fields,
  which the recorder did not need for this camera.
