package omadafront

import (
	"encoding/json"
	"net/http"
	"testing"
)

const intrusionRead = `{"method":"get","intrusion_detection":{"version":"1","name":["detection","notify_list","arming_schedule","feature"],"table":["polygon_region_info","region_info"]}}`

func TestVirtualIntrusionDetectionPassesSourceClassesAndIsAdvertised(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	code, response := request(t, s, path, intrusionRead)
	if code != http.StatusOK || response["error_code"] != float64(0) {
		t.Fatal("captured intrusion detection read was rejected")
	}
	intrusion := metadataObject(t, response["intrusion_detection"])
	if metadataObject(t, intrusion["detection"])["enabled"] != "on" || metadataObject(t, intrusion["notify_list"])["record_enabled"] != "on" ||
		metadataObject(t, intrusion["arming_schedule"])["sunday"] != `["0000-2400"]` || metadataObject(t, intrusion["feature"])["max_points_num"] != "16" {
		t.Fatal("intrusion detection defaults do not enable recording all day")
	}
	polygon := metadataObject(t, metadataObject(t, intrusion["polygon_region_info"].([]any)[0])["polygon_region_info_1"])
	rectangle := metadataObject(t, metadataObject(t, intrusion["region_info"].([]any)[0])["region_info_1"])
	for _, region := range []map[string]any{polygon, rectangle} {
		if region["people_enabled"] != "on" || region["vehicle_enabled"] != "on" || region["pet_enabled"] != "on" || region["obj_filter_enabled"] != "on" || region["id"] != float64(1) || region["percentage"] != float64(15) {
			t.Fatal("intrusion region does not pass every translated source class")
		}
	}
	if polygon["points_num"] != float64(4) || rectangle["pt2_x"] != float64(10000) {
		t.Fatal("intrusion region geometry differs from the whole frame")
	}
	_, capability := request(t, s, path, `{"method":"get","smart_detection":{"name":"capability"}}`)
	flags := metadataObject(t, metadataObject(t, capability["smart_detection"])["capability"])
	if flags["intrusion_detection"] != "1" || flags["linecrossing_detection"] != "1" || flags["people_detection"] != "0" || flags["smart_data"] != "0" || len(flags) != 21 {
		t.Fatal("smart detection capability does not match implemented rule modules")
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"set","intrusion_detection":{"detection":{"enabled":"off"}}}`)), &native); err != nil || native["error_code"] != float64(0) {
		t.Fatal("recorder intrusion write over the callback was rejected")
	}
	_, response = request(t, s, path, `{"method":"get","intrusion_detection":{"name":"detection"}}`)
	if metadataObject(t, metadataObject(t, response["intrusion_detection"])["detection"])["enabled"] != "off" {
		t.Fatal("intrusion write did not update the shared state")
	}
}

func TestVirtualMarkerBoxSwitchReadsAndWritesLikeTheCamera(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	_, response := request(t, s, path, `{"method":"get","marker_box":{"name":"detection"}}`)
	if response["error_code"] != float64(0) || metadataObject(t, metadataObject(t, response["marker_box"])["detection"])["enabled"] != "on" {
		t.Fatal("smart frame switch is not reported enabled like the real camera")
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"set","marker_box":{"detection":{"enabled":"off"}}}`)), &native); err != nil || native["error_code"] != float64(0) {
		t.Fatal("recorder smart frame write was rejected")
	}
	_, response = request(t, s, path, `{"method":"get","marker_box":{"name":"detection"}}`)
	if metadataObject(t, metadataObject(t, response["marker_box"])["detection"])["enabled"] != "off" {
		t.Fatal("smart frame write did not update the shared state")
	}
	if code, response := request(t, s, path, `{"method":"set","marker_box":{"preview_enabled":{"enabled":"on"}}}`); code != http.StatusOK || response["error_code"] != float64(unsupportedCode) {
		t.Fatal("unknown marker_box section was accepted")
	}
}
