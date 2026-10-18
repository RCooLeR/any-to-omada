package omadafront

import (
	"encoding/json"
	"slices"
)

// readModuleVocabulary lists names from captured NVR GETs and the inspected
// camera firmware default-node inventory. Video nodes also match its management
// registry. These are protocol names, not a list of implemented operations.
func readModuleVocabulary() map[string]string {
	return map[string]string{
		"OSD":                         "OSD",
		"ROI":                         "ROI",
		"abandonandtaken_detection":   "object_removal_detection",
		"abnormal_events":             "abnormal_events",
		"advance_settings_capability": "advance_settings_capability",
		"advance_settings_config":     "advance_settings_config",
		"ai_enhance_capability":       "ai_enhancement_capability",
		"alarm_audio_type_capability": "alarm_audio_type_capability",
		"alarm_input":                 "alarm_input",
		"alarm_output":                "alarm_output",
		"ams_vdr":                     "ams_vdr",
		"audio_capability":            "audio_capability",
		"audio_config":                "audio_configuration",
		"audioexception_detection":    "audio_exception_detection",
		"avts":                        "avts",
		"babycry_detection":           "baby_cry_detection",
		"bark_detection":              "bark_detection",
		"brand_spec":                  "brand_spec",
		"cet":                         "cet",
		"cloud_config":                "firmware_configuration",
		"cloud_sdk":                   "cloud_sdk",
		"cloud_status":                "firmware_status",
		"cover":                       "cover",
		"ddns_config":                 "ddns_config",
		"device_info":                 "device_info",
		"diagnose":                    "diagnose",
		"diagnose_capability":         "diagnose_capability",
		"email":                       "email",
		"exception_handling":          "exception_handling",
		"firewall":                    "firewall",
		"ftp_client":                  "ftp_client",
		"ftp_plan_advance":            "ftp_plan_advance",
		"ftp_record_plan":             "ftp_record_plan",
		"function":                    "capabilities",
		"glass_detection":             "glass_detection",
		"gpio":                        "gpio",
		"harddisk_manage":             "harddisk_manage",
		"http":                        "http",
		"http_cloud_smartdata":        "http_cloud_smartdata",
		"image":                       "image",
		"image_capability":            "image_capability",
		"intrusion_detection":         "intrusion_detection",
		"led":                         "led",
		"lens_mask":                   "lens_mask",
		"light_alarm_info_capability": "light_capability",
		"light_control":               "light_configuration",
		"linecrossing_detection":      "line_crossing_detection",
		"linkage_capability":          "linkage_capability",
		"lldp":                        "lldp",
		"loitering_detection":         "loitering_detection",
		"long_connect":                "long_connect",
		"lpr":                         "lpr",
		"marker_box":                  "marker_box",
		"meow_detection":              "meow_detection",
		"motion_detection":            "motion_detection",
		"motord":                      "motord",
		"msg_alarm":                   "alarm_configuration",
		"msg_alarm_plan":              "alarm_schedule",
		"msg_push":                    "msg_push",
		"msg_push_plan":               "msg_push_plan",
		"multicast":                   "multicast",
		"network":                     "network",
		"onvif":                       "onvif",
		"openapi":                     "openapi",
		"osd_capability":              "osd_capability",
		"osd_from_nvr":                "osd_from_nvr",
		"p2p":                         "p2p",
		"people_detection":            "people_detection",
		"pet_detection":               "pet_detection",
		"plan_advance":                "plan_advance",
		"playback":                    "playback",
		"protocol":                    "protocol",
		"queue_detection":             "queue_detection",
		"record_plan":                 "record_plan",
		"regionentrance_detection":    "region_entry_detection",
		"regionexiting_detection":     "region_exit_detection",
		"relay":                       "relay",
		"remote_log":                  "remote_log",
		"rtmp":                        "rtmp",
		"rtsp":                        "rtsp",
		"scenechange_detection":       "scene_change_detection",
		"smart_analysis":              "smart_analysis",
		"smart_detection":             "smart_detection",
		"snmp":                        "snmp",
		"sound_detection":             "sound_detection",
		"store_inspection":            "store_inspection",
		"system":                      "system",
		"tamper_detection":            "tamper_detection",
		"target_track":                "target_track",
		"telemetry":                   "telemetry",
		"timing_reboot":               "timing_reboot",
		"tmpd":                        "tmpd",
		"tums_config":                 "tums_config",
		"tums_msg_push":               "tums_msg_push",
		"uhttpd":                      "uhttpd",
		"uhttpd_ssl":                  "uhttpd_ssl",
		"unusual_detection":           "unusual_detection",
		"upgrade":                     "upgrade",
		"upnpc":                       "upnpc",
		"user_management":             "user_management",
		"usr_def_audio":               "usr_def_audio",
		"vehicle_detection":           "vehicle_detection",
		"video":                       "video",
		"video_capability":            "video_capability",
		"wait_time":                   "wait_time",
	}
}

// readSelectorVocabulary lists observed selector names for diagnostics,
// including operations that the translator does not implement.
func readSelectorVocabulary() map[string][]string {
	return map[string][]string{
		"OSD":                         {"azimuth", "date_info", "font_info", "label_info", "logo_info", "osd_state", "zoom"},
		"ROI":                         {"roi_enable"},
		"abandonandtaken_detection":   {"arming_schedule", "detection", "feature", "notify_list", "polygon_region_info", "region_info"},
		"abnormal_events":             {"on_off"},
		"advance_settings_capability": {"advance_settings_capability"},
		"advance_settings_config":     {"advance_settings_config"},
		"ai_enhance_capability":       {"traditional_enhance"},
		"alarm_audio_type_capability": {"capability"},
		"alarm_input":                 {"alarm_in_AI1", "arming_schedule_AI1", "notify_list_AI1"},
		"alarm_output":                {"alarm_out_AO1", "arming_schedule_AO1"},
		"ams_vdr":                     {"ams_common", "bgm_common", "dla", "dp_trajectory", "fg_common", "fg_hsv", "gmm", "object", "trajectory", "vdr_cd", "vdr_id", "vdr_md", "vdr_od_bgm_w", "vdr_pd_dla", "vdr_petd_dla", "vdr_vd_dla", "vframe"},
		"audio_capability":            {"device_microphone", "device_speaker"},
		"audio_config":                {"microphone", "record_audio", "speaker"},
		"audioexception_detection":    {"arming_schedule", "notify_list", "voice_rise"},
		"avts":                        {"avdm"},
		"babycry_detection":           {"detection"},
		"bark_detection":              {"detection"},
		"brand_spec":                  {"brand"},
		"cet":                         {"https", "rtsp", "vhttpd"},
		"cloud_config":                {"auto_check_fw_info", "cloud_device", "cloud_reply", "new_firmware", "router_post"},
		"cloud_sdk":                   {"cloud_sdk"},
		"cloud_status":                {"check_fw_ver"},
		"cover":                       {"cover_info"},
		"ddns_config":                 {"ddns_config"},
		"device_info":                 {"basic_info", "info"},
		"diagnose":                    {"diagnose_addr"},
		"diagnose_capability":         {"capability"},
		"email":                       {"smtp_info"},
		"exception_handling":          {"exception_handling"},
		"firewall":                    {"ipctrl"},
		"ftp_client":                  {"ftp_client"},
		"ftp_plan_advance":            {"ftp_plan_advance"},
		"ftp_record_plan":             {"chn1_channel", "week_plan"},
		"function":                    {"module_spec"},
		"glass_detection":             {"detection"},
		"gpio":                        {"gpio_cfg"},
		"harddisk_manage":             {"disk", "partition", "storage"},
		"http":                        {"http"},
		"http_cloud_smartdata":        {"cloud_smartdata"},
		"image":                       {"autoday_area_compensation_region_info", "autoday_bal_area_compensation_region_info", "autoday_bal_white_balance_region_info", "autoday_white_balance_region_info", "autonight_area_compensation_region_info", "autonight_bal_area_compensation_region_info", "autonight_bal_white_balance_region_info", "autonight_cll_area_compensation_region_info", "autonight_cll_white_balance_region_info", "autonight_por_area_compensation_region_info", "autonight_por_white_balance_region_info", "autonight_squ_area_compensation_region_info", "autonight_squ_white_balance_region_info", "autonight_white_balance_region_info", "common_area_compensation_region_info", "common_bal_area_compensation_region_info", "common_bal_white_balance_region_info", "common_white_balance_region_info", "image_mode", "para", "shedday_area_compensation_region_info", "shedday_bal_area_compensation_region_info", "shedday_bal_white_balance_region_info", "shedday_white_balance_region_info", "shednight_area_compensation_region_info", "shednight_bal_area_compensation_region_info", "shednight_bal_white_balance_region_info", "shednight_cll_area_compensation_region_info", "shednight_cll_white_balance_region_info", "shednight_por_area_compensation_region_info", "shednight_por_white_balance_region_info", "shednight_squ_area_compensation_region_info", "shednight_squ_white_balance_region_info", "shednight_white_balance_region_info", "switch", "switch_type", "video_format"},
		"image_capability":            {"advanced", "capability", "preview_full_color", "smart_white_lamp", "supplement_lamp"},
		"intrusion_detection":         {"arming_schedule", "detection", "ebike_info", "feature", "notify_list", "on_off", "plan", "polygon_region_info", "region_info", "sound_alarm_info"},
		"led":                         {"config"},
		"lens_mask":                   {"lens_mask_info"},
		"light_alarm_info_capability": {"capability"},
		"light_control":               {"light_alarm_info", "white_light_manual"},
		"linecrossing_detection":      {"arming_schedule", "detection", "notify_list", "on_off", "plan", "polyline_region_info", "region_info", "sound_alarm_info"},
		"linkage_capability":          {"capability"},
		"lldp":                        {"lldp_config"},
		"loitering_detection":         {"arming_schedule", "detection", "feature", "notify_list", "polygon_region_info", "region_info"},
		"long_connect":                {"remote_config"},
		"lpr":                         {"device_linkage_info", "lp_matching_para", "lpr_filter"},
		"marker_box":                  {"detection", "preview_enabled"},
		"meow_detection":              {"detection"},
		"motion_detection":            {"arming_schedule", "feature", "md_polygon_region_info", "md_sensitivity", "motion_det", "motion_notif_list", "notif_list", "on_off", "plan", "polygon_region_info", "region_info", "sound_alarm_info"},
		"motord":                      {"motord"},
		"msg_alarm":                   {"arming_status", "chn1_msg_alarm_info", "config", "info"},
		"msg_alarm_plan":              {"arming_schedule_light", "arming_schedule_sound", "plan"},
		"msg_push":                    {"msg_push"},
		"msg_push_plan":               {"plan"},
		"multicast":                   {"multicast"},
		"network":                     {"eap_capability", "if_config", "wan_status"},
		"onvif":                       {"adconf", "asconf", "dis_mode", "mdconf", "onvif_function", "profile", "recordconf", "recording_options", "track", "vsconf"},
		"openapi":                     {"msgpush", "server"},
		"osd_capability":              {"capability"},
		"osd_from_nvr":                {"nvr_info", "ttf_info"},
		"p2p":                         {"server"},
		"people_detection":            {"arming_schedule", "detection", "feature", "notify_list", "plan", "polygon_region_info", "region_info", "sound_alarm_info"},
		"pet_detection":               {"arming_schedule", "detection", "feature", "notify_list", "plan", "region_info", "sound_alarm_info"},
		"plan_advance":                {"plan_advance"},
		"playback":                    {"scale_capability"},
		"protocol":                    {"interface", "proto"},
		"queue_detection":             {"detection", "feature", "polygon_region_info"},
		"record_plan":                 {"chn1_channel", "feature", "week_plan"},
		"regionentrance_detection":    {"arming_schedule", "detection", "feature", "notify_list", "polygon_region_info", "region_info"},
		"regionexiting_detection":     {"arming_schedule", "detection", "feature", "notify_list", "polygon_region_info", "region_info"},
		"relay":                       {"server"},
		"remote_log":                  {"remote_config"},
		"rtmp":                        {"rtmp"},
		"rtsp":                        {"rtsp"},
		"scenechange_detection":       {"arming_schedule", "detection", "notify_list"},
		"smart_analysis":              {"capability", "detection", "feature", "hd_capability"},
		"smart_detection":             {"capability"},
		"snmp":                        {"snmp"},
		"sound_detection":             {"arming_schedule", "notify_list"},
		"store_inspection":            {"detection"},
		"system":                      {"sys", "system", "time_status"},
		"tamper_detection":            {"notif_list", "od_sensitivity", "on_off", "sound_alarm_info", "tamper_det", "tamper_notif_list"},
		"target_track":                {"fov_info", "target_track_info"},
		"telemetry":                   {"telemetry"},
		"timing_reboot":               {"reboot"},
		"tmpd":                        {"tmpd"},
		"tums_config":                 {"tums_config"},
		"tums_msg_push":               {"tums_msg_push"},
		"uhttpd":                      {"uhttpd"},
		"uhttpd_ssl":                  {"uhttpd_ssl"},
		"unusual_detection":           {"login_error_detection"},
		"upgrade":                     {"upgrade_status"},
		"upnpc":                       {"entry", "on_off"},
		"user_management":             {"root", "third_account"},
		"usr_def_audio":               {"usr_def_audio_config"},
		"vehicle_detection":           {"arming_schedule", "detection", "feature", "notify_list", "plan", "polygon_region_info", "region_info", "sound_alarm_info"},
		"video":                       {"common", "jpeg", "main", "minor", "stream", "third"},
		"video_capability":            {"capability", "jpeg", "main", "minor"},
		"wait_time":                   {"wait_time"},
	}
}

// readModuleLabels emits only fixed vocabulary labels. Request values, unknown
// module names and unrelated fields never enter a diagnostic label.
func readModuleLabels(request map[string]json.RawMessage) []string {
	known := readModuleVocabulary()
	labels := make(map[string]bool)
	for module := range request {
		if module == "method" {
			continue
		}
		if label, ok := known[module]; ok {
			labels[label] = true
		} else {
			labels["unknown"] = true
		}
	}
	return boundedReadLabels(labels, 8)
}

// readSelectorLabels reports bounded known selector labels and input forms,
// counting unknown modules without emitting their supplied names.
func readSelectorLabels(request map[string]json.RawMessage) (labels, forms []string, unknownModules int) {
	knownModules := readModuleVocabulary()
	knownSelectors := readSelectorVocabulary()
	labelSet, formSet := make(map[string]bool), make(map[string]bool)
	for module, raw := range request {
		if module == "method" {
			continue
		}
		if _, ok := knownModules[module]; !ok {
			unknownModules++
			labelSet["unknown"] = true
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			labelSet[module+":invalid"] = true
			continue
		}
		found := false
		for _, field := range []string{"name", "table"} {
			value, ok := fields[field]
			if !ok {
				continue
			}
			found = true
			prefix := module + "." + field + ":"
			var scalar string
			var values []json.RawMessage
			switch {
			case len(value) > 0 && value[0] == '"' && json.Unmarshal(value, &scalar) == nil:
				formSet[field+":string"] = true
				addReadSelectorLabel(labelSet, knownSelectors[module], prefix, scalar)
			case len(value) > 0 && value[0] == '[' && json.Unmarshal(value, &values) == nil:
				formSet[field+":array"] = true
				if len(values) == 0 {
					labelSet[prefix+"empty"] = true
				}
				for _, item := range values {
					if len(item) == 0 || item[0] != '"' || json.Unmarshal(item, &scalar) != nil {
						labelSet[prefix+"invalid"] = true
						continue
					}
					addReadSelectorLabel(labelSet, knownSelectors[module], prefix, scalar)
				}
			default:
				formSet["invalid"] = true
				labelSet[prefix+"invalid"] = true
			}
		}
		if !found {
			labelSet[module+":no_selector"] = true
		}
	}
	return boundedReadLabels(labelSet, 16), boundedReadLabels(formSet, 5), unknownModules
}

// addReadSelectorLabel adds a known selector or a fixed unknown marker;
// prefix must already come from the approved module/selector vocabulary.
func addReadSelectorLabel(labels map[string]bool, known []string, prefix, value string) {
	if slices.Contains(known, value) {
		labels[prefix+value] = true
	} else {
		labels[prefix+"unknown"] = true
	}
}

// boundedReadLabels sorts and bounds diagnostic labels while retaining an
// unknown marker; callers supply enough capacity for truncation markers.
func boundedReadLabels(set map[string]bool, limit int) []string {
	labels := make([]string, 0, len(set))
	unknown := set["unknown"]
	for label := range set {
		if label != "unknown" {
			labels = append(labels, label)
		}
	}
	slices.Sort(labels)
	if unknown {
		limit--
	}
	if len(labels) > limit {
		labels = append(labels[:limit-1], "truncated")
	}
	if unknown {
		labels = append(labels, "unknown")
	}
	slices.Sort(labels)
	return labels
}
