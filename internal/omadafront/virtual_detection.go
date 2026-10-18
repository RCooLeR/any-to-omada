package omadafront

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const (
	maxDetectionLeaves = 32
	maxDetectionRows   = 16
	maxDetectionText   = 512
)

// virtualDetectionState emulates the recorder-facing motion, tamper, intrusion,
// line crossing and smart-frame (marker_box) settings of one virtual camera,
// following the section and leaf names the real Omada camera returned. Defaults
// pass all mapped source detections and enable recording in every notify list.
// Region geometry is virtual: the physical source determines rule crossings.
// The recorder stores a camera's alarms only after these reads succeed (see
// docs/omada-protocol.md). The settings decide which alarm starts the
// translator forwards (Server.EventAllowed) and can be changed from the
// recorder UI. State is in memory and resets on restart; nothing is forwarded
// to the physical source.
type virtualDetectionState struct {
	mu      sync.Mutex
	modules map[string]*detectionModule
}

type detectionModule struct {
	sections map[string]map[string]any
	tables   map[string][]any
}

func allDaySchedule() map[string]any {
	schedule := map[string]any{}
	for _, day := range []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"} {
		// The camera stores each day as a JSON array of HHMM ranges inside a
		// string; the wire percent-encodes it like every other string value.
		schedule[day] = `["0000-2400"]`
	}
	return schedule
}

func notifyList(extra ...string) map[string]any {
	list := map[string]any{"client_enabled": "off", "app_enabled": "off", "msg_push_enabled": "on", "sound_alarm_enabled": "off",
		"light_alarm_enabled": "off", "record_enabled": "on", "AO1_enabled": "off", "ftp_enabled": "off", "capture_enabled": "off",
		"email_enabled": "off", "report_server_enabled": "off"}
	for _, name := range extra {
		list[name] = "off"
	}
	return list
}

func fullFramePolygon(key string) []any {
	return []any{map[string]any{key: map[string]any{"points_num": 4, "points_x": []any{0, 10000, 10000, 0}, "points_y": []any{10000, 10000, 0, 0}}}}
}

func newVirtualDetectionState() *virtualDetectionState {
	return &virtualDetectionState{modules: map[string]*detectionModule{
		"motion_detection": {
			sections: map[string]map[string]any{
				"motion_det": {"enabled": "on", "sensitivity": "medium", "digital_sensitivity": 50, "people_enabled": "on", "vehicle_enabled": "on",
					"pet_enabled": "on", "non_vehicle_enabled": "off", "target_validity": "medium", "obj_filter_enabled": "on",
					"min_target_width": 0, "max_target_width": 10000, "min_target_height": 0, "max_target_height": 10000, "mb_enabled": "off"},
				"arming_schedule":   allDaySchedule(),
				"motion_notif_list": notifyList("target_track_enabled"),
				"feature":           {"max_points_num": "16"},
			},
			tables: map[string][]any{
				"md_polygon_region_info": fullFramePolygon("md_polygon_region_info_1"),
				"polygon_region_info":    fullFramePolygon("polygon_region_info_1"),
				"region_info":            {map[string]any{"region_info_1": map[string]any{"x_coor": 0, "y_coor": 0, "width": 10000, "height": 10000}}},
			},
		},
		"tamper_detection": {
			sections: map[string]map[string]any{
				"tamper_det":        {"enabled": "on", "sensitivity": "medium", "digital_sensitivity": "50"},
				"tamper_notif_list": notifyList(),
			},
			tables: map[string][]any{},
		},
		// marker_box is the camera's "smart frame" switch for the per-frame target
		// metadata. The real camera reported it enabled; the recorder writes it
		// when the operator toggles smart frame for the channel.
		"marker_box": {
			sections: map[string]map[string]any{"detection": {"enabled": "on"}},
			tables:   map[string][]any{},
		},
		// The whole frame represents the source camera's intrusion rules; its
		// native event classification decides when an alarm is raised.
		"intrusion_detection": {
			sections: map[string]map[string]any{
				"detection":       {"enabled": "on"},
				"notify_list":     notifyList("target_track_enabled"),
				"arming_schedule": allDaySchedule(),
				"feature":         {"max_points_num": "16"},
			},
			tables: map[string][]any{
				"polygon_region_info": {map[string]any{"polygon_region_info_1": intrusionRegion(map[string]any{
					"points_num": 4, "points_x": []any{0, 10000, 10000, 0}, "points_y": []any{10000, 10000, 0, 0}})}},
				"region_info": {map[string]any{"region_info_1": intrusionRegion(map[string]any{
					"pt1_x": 0, "pt1_y": 10000, "pt2_x": 10000, "pt2_y": 10000, "pt3_x": 10000, "pt3_y": 0, "pt4_x": 0, "pt4_y": 0})}},
			},
		},
		"linecrossing_detection": {
			sections: map[string]map[string]any{
				"detection":       {"enabled": "on"},
				"notify_list":     notifyList("target_track_enabled"),
				"arming_schedule": allDaySchedule(),
			},
			tables: map[string][]any{
				"polyline_region_info": {map[string]any{"polyline_region_info_1": lineRegion(map[string]any{
					"points_num": 2, "points_x": []any{5000, 5000, 0, 0, 0}, "points_y": []any{0, 10000, 0, 0, 0}})}},
				"region_info": {map[string]any{"region_info_1": lineRegion(map[string]any{
					"pt1_x": 5000, "pt1_y": 0, "pt2_x": 5000, "pt2_y": 10000})}},
			},
		},
	}}
}

// intrusionRegion returns the donor's region leaves with each translated class
// enabled, merged with virtual geometry.
func intrusionRegion(geometry map[string]any) map[string]any {
	region := map[string]any{"id": 1, "sensitivity": 50, "threshold": 0, "percentage": 15,
		"position_pan": 0.0, "position_tilt": 0.0, "position_zoom": 0.0,
		"people_enabled": "on", "vehicle_enabled": "on", "pet_enabled": "on", "ebike_enabled": "off", "constant_alarm_enabled": "off",
		"non_vehicle_enabled": "off", "target_validity": "medium", "obj_filter_enabled": "on",
		"min_target_width": 0, "max_target_width": 10000, "min_target_height": 0, "max_target_height": 10000}
	for name, value := range geometry {
		region[name] = value
	}
	return region
}

// lineRegion uses the observed polyline fields, without inventing coordinates
// for the source camera's rule. These coordinates belong only to the virtual UI.
func lineRegion(geometry map[string]any) map[string]any {
	region := map[string]any{"id": 1, "sensitivity": 50, "direction": "both",
		"position_pan": 0.0, "position_tilt": 0.0, "position_zoom": 0.0,
		"people_enabled": "on", "vehicle_enabled": "on", "pet_enabled": "on", "non_vehicle_enabled": "off",
		"target_validity": "medium", "obj_filter_enabled": "on",
		"min_target_width": 0, "max_target_width": 10000, "min_target_height": 0, "max_target_height": 10000}
	for name, value := range geometry {
		region[name] = value
	}
	return region
}

// smartDetectionCapability lists the detection types the virtual camera
// implements: line crossing and intrusion, backed by native source events.
// Everything else is reported unsupported. smartData
// reports the per-frame marker metadata flag the Omada camera sets.
func smartDetectionCapability(smartData bool) map[string]any {
	capability := map[string]any{}
	for _, name := range []string{"linecrossing_detection", "intrusion_detection", "regionentrance_detection", "regionexiting_detection",
		"loitering_detection", "fastmoving_detection", "parking_detection", "unattendedbaggage_detection", "abandonandtaken_detection",
		"objectremove_detection", "face_detection", "scenechange_detection", "defocus_detection", "audioabnormal_detection",
		"overline_detection", "vehicle_detection", "smart_data", "people_detection", "people_detection_capability",
		"peoplevisit_detection", "pet_detection"} {
		capability[name] = "0"
	}
	capability["intrusion_detection"] = "1"
	capability["linecrossing_detection"] = "1"
	if smartData {
		capability["smart_data"] = "1"
	}
	return capability
}

// observedLinkageCapability returns the Omada camera's linkage bit strings.
func observedLinkageCapability() map[string]any {
	alarm := "010000000001000001100000000000001111"
	return map[string]any{"sound_alarm_capability": alarm, "light_alarm_capability": alarm,
		"record_capability": "010000000001000101100000000000001111", "msg_push_capability": "000000000001001000000000000000001111",
		"ftp_capability": alarm, "email_capability": alarm, "report_server_capability": "000000000000000000000000000000000000"}
}

// read returns a detached copy of one named section.
func (v *virtualDetectionState) read(module, name string) (any, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.modules[module]
	if m == nil {
		return nil, false
	}
	section, ok := m.sections[name]
	if !ok {
		return nil, false
	}
	return copyLeaves(section), true
}

// table returns a detached copy of one region table.
func (v *virtualDetectionState) table(module, name string) ([]any, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.modules[module]
	if m == nil {
		return nil, false
	}
	rows, ok := m.tables[name]
	if !ok {
		return nil, false
	}
	result := make([]any, len(rows))
	copy(result, rows)
	return result, true
}

// write applies a settings write (method set) or the observed region operation
// (method do, add_*regions) addressed to exactly one detection module. Every
// section, leaf and value is validated before any change; unknown sections or
// operations and oversized or non-scalar values reject the whole request so
// the recorder sees an unsupported operation.
func (v *virtualDetectionState) write(method string, request map[string]json.RawMessage) bool {
	if (method != "set" && method != "do") || len(request) != 2 {
		return false
	}
	var module string
	var raw json.RawMessage
	for name, value := range request {
		if name != "method" {
			module, raw = name, value
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.modules[module]
	if m == nil {
		return false
	}
	var operations map[string]json.RawMessage
	if json.Unmarshal(raw, &operations) != nil || len(operations) == 0 || len(operations) > 8 {
		return false
	}
	if method == "set" {
		updates := map[string]map[string]any{}
		for section, body := range operations {
			current, known := m.sections[section]
			if !known {
				return false
			}
			leaves, ok := decodeLeaves(body)
			if !ok || len(current)+len(leaves) > maxDetectionLeaves*2 {
				return false
			}
			updates[section] = leaves
		}
		for section, leaves := range updates {
			for leaf, value := range leaves {
				m.sections[section][leaf] = value
			}
		}
		return true
	}
	replacements := map[string][]any{}
	for operation, body := range operations {
		table, ok := regionTable(operation)
		if !ok {
			return false
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(body, &payload) != nil || len(payload) != 1 {
			return false
		}
		rowsRaw, present := payload[table]
		if _, known := m.tables[table]; !present || !known {
			return false
		}
		var rows []json.RawMessage
		if json.Unmarshal(rowsRaw, &rows) != nil || len(rows) > maxDetectionRows {
			return false
		}
		// The recorder sends the complete region list, which replaces the table.
		// The camera keys stored rows by table name and ordinal.
		converted := make([]any, 0, len(rows))
		for i, row := range rows {
			leaves, ok := decodeLeaves(row)
			if !ok {
				return false
			}
			converted = append(converted, map[string]any{table + "_" + strconv.Itoa(i+1): leaves})
		}
		replacements[table] = converted
	}
	for table, rows := range replacements {
		m.tables[table] = rows
	}
	return true
}

// regionTable maps the observed add_*regions operations to the table they
// replace. Other region operations have not been observed and are rejected.
func regionTable(operation string) (string, bool) {
	switch operation {
	case "add_polygon_regions":
		return "polygon_region_info", true
	case "add_polyline_regions":
		return "polyline_region_info", true
	case "add_md_polygon_regions":
		return "md_polygon_region_info", true
	case "add_regions":
		return "region_info", true
	default:
		return "", false
	}
}

// decodeLeaves accepts an object of scalar leaves or small numeric arrays.
// Strings that still carry percent escapes (HTTPS requests) are decoded once,
// matching the camera's treatment of request values.
func decodeLeaves(raw json.RawMessage) (map[string]any, bool) {
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&fields) != nil || fields == nil || len(fields) > maxDetectionLeaves {
		return nil, false
	}
	for name, value := range fields {
		if name == "" || len(name) > 64 {
			return nil, false
		}
		switch typed := value.(type) {
		case string:
			if len(typed) > maxDetectionText {
				return nil, false
			}
			if strings.Contains(typed, "%") {
				if decoded, err := url.PathUnescape(typed); err == nil {
					typed = decoded
				}
			}
			fields[name] = typed
		case json.Number, bool:
		case []any:
			if len(typed) > 64 {
				return nil, false
			}
			for _, item := range typed {
				if _, ok := item.(json.Number); !ok {
					return nil, false
				}
			}
		default:
			return nil, false
		}
	}
	return fields, true
}

func copyLeaves(section map[string]any) map[string]any {
	result := make(map[string]any, len(section))
	for name, value := range section {
		result[name] = value
	}
	return result
}

// enabledLeaf reports whether a section's enabled leaf is "on".
func (v *virtualDetectionState) enabledLeaf(module, section, leaf string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.modules[module]
	if m == nil {
		return false
	}
	value, _ := m.sections[section][leaf].(string)
	return value == "on"
}

// regionAllows checks the target-class flag only in the selected region format.
// The polygon and rectangle tables are alternative representations, not a union
// of active rules; an unused table must not override the configured class filter.
func (v *virtualDetectionState) regionAllows(module, table, flag string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.modules[module]
	if m == nil {
		return false
	}
	for _, row := range m.tables[table] {
		entry, _ := row.(map[string]any)
		for _, fields := range entry {
			leaves, _ := fields.(map[string]any)
			if flag == "" && len(leaves) > 0 {
				return true
			}
			if value, _ := leaves[flag].(string); value == "on" {
				return true
			}
		}
	}
	return false
}

// EventAllowed reports whether the virtual camera's detection settings enable
// an alarm start of the given native type: plain and classified motion need
// motion detection on (and the class enabled in motion_det); classified
// intrusion and line crossing need their detection on and a region with the
// class enabled. An unclassified rule alarm requires at least one active region.
// Stop edges are not gated by callers, matching the real camera, which sends
// stops for detections whose starts it does not report.
func (s *Server) EventAllowed(eventType omadalink.EventType) bool {
	motion := func(flag string) bool {
		return s.virtualDetect.enabledLeaf("motion_detection", "motion_det", "enabled") &&
			(flag == "" || s.virtualDetect.enabledLeaf("motion_detection", "motion_det", flag))
	}
	rule := func(module, polygonTable, flag string) bool {
		// The vendor UI selects the region API using detection_polygon_enable,
		// which is advertised only by our observed module_spec profile.
		table := "region_info"
		if s.compat.ObservedModuleSpec {
			table = polygonTable
		}
		return s.virtualDetect.enabledLeaf(module, "detection", "enabled") && s.virtualDetect.regionAllows(module, table, flag)
	}
	switch eventType {
	case omadalink.EventTamper:
		return s.virtualDetect.enabledLeaf("tamper_detection", "tamper_det", "enabled")
	case omadalink.EventMotion:
		return motion("")
	case omadalink.EventHumanMotion:
		return motion("people_enabled")
	case omadalink.EventVehicleMotion:
		return motion("vehicle_enabled")
	case omadalink.EventPetMotion:
		return motion("pet_enabled")
	case omadalink.EventIntrusion:
		return rule("intrusion_detection", "polygon_region_info", "")
	case omadalink.EventHumanIntrusion:
		return rule("intrusion_detection", "polygon_region_info", "people_enabled")
	case omadalink.EventVehicleIntrusion:
		return rule("intrusion_detection", "polygon_region_info", "vehicle_enabled")
	case omadalink.EventPetIntrusion:
		return rule("intrusion_detection", "polygon_region_info", "pet_enabled")
	case omadalink.EventLineCrossing:
		return rule("linecrossing_detection", "polyline_region_info", "")
	case omadalink.EventHumanLine:
		return rule("linecrossing_detection", "polyline_region_info", "people_enabled")
	case omadalink.EventVehicleLine:
		return rule("linecrossing_detection", "polyline_region_info", "vehicle_enabled")
	case omadalink.EventPetLine:
		return rule("linecrossing_detection", "polyline_region_info", "pet_enabled")
	default:
		return false
	}
}
