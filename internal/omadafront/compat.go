package omadafront

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Compatibility enables bounded recorder-compatibility experiments. Every field
// is off by default. Enabled options describe the virtual camera with values the
// physical source cannot confirm; they exist to isolate which recorder
// expectation blocks stream creation and must not be mistaken for source facts.
type Compatibility struct {
	// ObservedModuleSpec advertises the function.module_spec set observed from
	// an Omada 8MP Turret (firmware 1.0.7) instead of implemented features only.
	ObservedModuleSpec bool
	// AdvertiseVHTTPD reports the native vhttpd 8800 service in CET and UPnP.
	// No listener exists; the recorder opened no 8800 connection in captures.
	AdvertiseVHTTPD bool
	// ExtendedVideoFields adds the donor's optional encoder leaves with virtual values.
	ExtendedVideoFields bool
	// ExtendedIdentity adds hardware version, region counts and stable virtual
	// identifiers derived from the camera name, never copied from a donor.
	ExtendedIdentity bool
	// ManufacturerName overrides the reported manufacturer; empty keeps AnyToOmada.
	ManufacturerName string
	// EncodeHTTPStrings percent-encodes HTTPS response string values exactly as
	// the native camera does. Native passthrough responses are always encoded.
	EncodeHTTPStrings bool
	// Netmask, Gateway and DNS describe the virtual interface's network in
	// wan_status when all three are set.
	Netmask, Gateway, DNS string
	// PTZModuleSpecKeys adds these function.module_spec keys with value "1"
	// while a PTZ controller is configured, to find which ones make the
	// recorder offer PTZ controls.
	PTZModuleSpecKeys []string
}

type service struct{ name, port string }

func (c Compatibility) networkConfigured() bool {
	return c.Netmask != "" && c.Gateway != "" && c.DNS != ""
}

// observedModuleSpec returns the capability set captured from the donor camera
// on 2026-10-16. Two captured members (change_password and
// verification_change_password) were redacted and are omitted rather than
// invented. The native callback version and session limit stay ours.
func observedModuleSpec(callbackVersion string) map[string]any {
	return map[string]any{
		"advance_settings_capability": "1", "ae_weighting_table_resolution": "5*5", "ai_enhance_capability": "1",
		"ai_enhance_range": []string{"traditional_enhance"}, "aio_hw_support": "1",
		"alarm_in_enable": "0", "alarm_in_num": "0", "alarm_out_enable": "0", "alarm_out_num": "0",
		"alg_event_property": []string{"object_filter", "object_filter_enabled"}, "app_version": "1.0.0",
		"audio": []string{"speaker", "microphone"}, "audio_init_config_support": "1", "auth_encrypt": "1",
		"auto_chk_fw": "1", "auto_ip_configurable": "1", "backlight_coexistence": "1", "client_info": "0",
		"cloud_server_crt": "2.0", "cloud_storage_version": "1.0", "conf_packet_encrypt": "1.1",
		"config_recovery": []string{"audio_config", "image", "ROI", "OSD", "video", "upnpc", "firewall", "email", "ddns_config", "ftp_client", "long_connect"},
		"corridor_mode":   "1", "custom_area_compensation": "1", "daynight_subdivision": "1", "ddns": "1",
		"detection_polygon_enable": "1", "device_share": []string{"preview", "playback", "voice", "cloud_storage"},
		"dhcpc_ver": "1.0", "digest_switch": "1", "download": []string{"video"}, "email_enable": "1",
		"events": []string{"motion", "tamper"}, "extend_snmp_v1_v3_support": "1", "firewall_mac": "1",
		"flicker_support_version": "1", "force_iframe_support": "1", "ftp_client": []string{"picture", "video"},
		"http_smartdata_version": "1.0", "http_system_state_audio_support": "1", "ieee8021x_enable": "1",
		"image_capability": "1", "image_list": []string{"expose", "supplement_lamp", "smart_white_lamp", "preview_full_color", "image_style", "advanced"},
		"ipc_platform_version": "2.1", "ipv6_support": "1", "ir_exposure_control": "1",
		"language_capability": []string{"English", "Bulgarian", "Czech", "German", "Spanish Latin America", "French", "Hungarian", "Japanese", "Korean", "Polish", "Brazilian Portuguese", "Romanian", "Russian", "Slovak", "Serbian", "Thai", "Turkish", "Ukrainian", "Vietnamese", "Traditional Chinese", "Italian", "Spanish", "Portuguese", "Arabic"},
		"lens_mask":           "0", "light_alarm_version": "1.2", "linecrossing_detection_polyline_region_capability": "1",
		"linkage_capability": "1", "lldp": "1", "local_https_streams_support": "1", "local_storage": "1",
		"marker_box": "1", "marker_box_type": "1001111", "media_encrypt": "1",
		"motion_detection_arming_schedule_support": "1", "motion_detection_polygon_region_capability": "1",
		"msg_alarm_separate_list": []string{"sound", "light"}, "msg_alarm_ver": "1.0", "msg_push": "1", "multi_user": "2",
		"network": []string{"ethernet"}, "ntp_setting": "1", "nvr_long_connect": callbackVersion, "omada_ipc": "1.0",
		"onvif_notify_cfg_change": "1", "onvif_notify_version": "3", "onvif_time_verification_support": "1",
		"openapi_support": "1", "osd_capability": "1", "osd_multi_language": "1", "ota_upgrade": "1",
		"p2p_support_versions": []string{"1.2"}, "pa_ver": "1.0", "playback": []string{"local", "p2p", "relay"},
		"playback_scale": "1", "playback_target_types": []string{"people", "vehicle", "pet"}, "playback_version": "1.5",
		"preview": []string{"local", "p2p", "relay"}, "privacy_mask_api_version": "1.0", "privacy_mosaic": "1",
		"pwd_rule_ver": "1.1", "record_max_slot_cnt": "10", "record_type": []string{"timing", "motion"},
		"relay_cdn_version": "1", "relay_support_versions": []string{"1.3"}, "relay_version": "2.0",
		"remote_storage": "1", "remote_upgrade": "1", "rtmp_support": "1", "sd_card_hardware_encrypt_support": "0",
		"smart_codec": "1", "smart_detection": "1", "smart_ir_exposure_control": "1", "smart_msg_push_capability": "1",
		"snapshot_version": "1.0", "snmp_support": "1", "sound_alarm_version": "1.1", "ssl_cer_version": "1.0",
		"storage_api_version": "2.3", "store_inspection": "1", "stream_max_sessions": "8", "stream_opz_ver": "2.0",
		"stream_protocol": []string{"srtp", "dash"}, "streaming_support_versions": []string{"1.1"},
		"support_inform_url": "1", "support_vms_fw_version": "2.0", "tdcp_version": "1.0",
		"time_date_format_support": "1", "time_date_format_ver": "1.0", "timing_reboot": "1", "timing_reboot_version": "1.2",
		"tplink_ddns": "1.0", "tums_config": "1", "tums_msg_push": "1", "tums_support": "1", "ueip": "1",
		"usr_def_audio_alarm": "1", "video_codec": []string{"h264", "h265"}, "video_detection_digital_sensitivity": "1",
		"video_share": "1", "web_pull_stream_ver": "1.0", "wide_range_inf_sensitivity": "1",
	}
}

// extendWANStatus adds the virtual interface's network settings with the
// donor's field names and integer link counters. No traffic is measured.
func (c Compatibility) extendWANStatus(wan map[string]any) {
	if !c.networkConfigured() {
		return
	}
	wan["netmask"], wan["gateway"], wan["pri_dns"], wan["snd_dns"] = c.Netmask, c.Gateway, c.DNS, "0.0.0.0"
	wan["internet_status"], wan["up_speed"], wan["down_speed"] = 0, 0, 0
	wan["pppoe_link_status"], wan["pppoe_ipv4"] = 0, "0.0.0.0"
}

// extendVideoFields adds the donor's optional encoder leaves. Smart codec and
// adaptive mode are off because the translator forwards the source encoding
// unchanged; the default bitrate is the current virtual bitrate.
func (c Compatibility) extendVideoFields(name string, fields map[string]any) {
	if !c.ExtendedVideoFields {
		return
	}
	if name == "main" {
		fields["smart_codec"], fields["adaptive_mode"] = "off", "off"
		if bitrate, ok := fields["bitrate"]; ok {
			fields["default_bitrate"] = bitrate
		}
		return
	}
	fields["socialshare_auto_h264"] = "0"
}

// extendIdentity adds hardware and registration fields with stable virtual
// identifiers derived from the camera name. They identify the virtual camera
// consistently across restarts and are never a donor's serial or device ID.
func (c Compatibility) extendIdentity(name string, body map[string]any, cameraName string) {
	if !c.ExtendedIdentity {
		return
	}
	model, _ := body["device_model"].(string)
	firmware, _ := body["sw_version"].(string)
	body["hw_version"] = "1.0"
	if name == "basic_info" {
		body["device_info"] = model + " 1.0 IPC"
		body["features"], body["region"], body["imei"], body["passwdType"] = 3, "UN", "", "md5"
		body["barcode"] = virtualIdentifier(cameraName, "barcode", 20)
		body["dev_id"] = virtualIdentifier(cameraName, "dev_id", 40)
		body["hw_id"] = virtualIdentifier(cameraName, "hw_id", 32)
		body["fw_cur_id"] = virtualIdentifier(cameraName, "fw_cur_id", 32)
		body["oem_id"] = virtualIdentifier(cameraName, "oem_id", 32)
		return
	}
	body["model_description"] = "IPC"
	body["devcode"] = virtualIdentifier(cameraName, "barcode", 20)
	body["sn"] = "ATO" + virtualIdentifier(cameraName, "serial", 10)
	body["cover_reg_num"], body["md_reg_num"], body["roi_reg_num"], body["isp_version"] = 4, 32, 0, 1
	body["isp_sw_version"] = firmware
}

func virtualIdentifier(cameraName, field string, length int) string {
	sum := sha256.Sum256([]byte("any-to-omada/virtual-identity/" + field + "/" + cameraName))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[:length]
}

// services lists the advertised virtual listeners for CET and UPnP. Only the
// implemented HTTPS and RTSP ports are reported unless vhttpd advertising is on.
func (c Compatibility) services() []service {
	services := []service{{"uhttpd", "443"}, {"rtsp", "554"}}
	if c.AdvertiseVHTTPD {
		services = append(services, service{"onvif_service", "2020"}, service{"vhttpd", "8800"}, service{"vhttpsd", "8443"})
	}
	return services
}
