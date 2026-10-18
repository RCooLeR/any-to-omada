package omadafront

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const detectionRead = `{"method":"get","motion_detection":{"version":"1","name":["motion_det","arming_schedule","motion_notif_list","feature"],"table":["md_polygon_region_info","polygon_region_info","region_info"]}}`

func TestVirtualDetectionReportsEnabledMotionWithRecordingOnBothTransports(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	code, response := request(t, s, path, detectionRead)
	if code != http.StatusOK || response["error_code"] != float64(0) {
		t.Fatal("captured motion detection read was rejected")
	}
	motion := metadataObject(t, response["motion_detection"])
	det := metadataObject(t, motion["motion_det"])
	notify := metadataObject(t, motion["motion_notif_list"])
	schedule := metadataObject(t, motion["arming_schedule"])
	if det["enabled"] != "on" || det["people_enabled"] != "on" || det["digital_sensitivity"] != float64(50) || notify["record_enabled"] != "on" ||
		schedule["monday"] != `["0000-2400"]` || metadataObject(t, motion["feature"])["max_points_num"] != "16" {
		t.Fatal("default motion detection is not enabled for every class with recording")
	}
	for _, table := range []string{"md_polygon_region_info", "polygon_region_info", "region_info"} {
		rows, ok := motion[table].([]any)
		if !ok || len(rows) != 1 {
			t.Fatalf("table %s missing its full-frame default row", table)
		}
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(detectionRead)), &native); err != nil {
		t.Fatal(err)
	}
	nativeSchedule := metadataObject(t, metadataObject(t, native["motion_detection"])["arming_schedule"])
	if nativeSchedule["monday"] != `["0000-2400"]` {
		t.Fatal("native passthrough schedule differs before wire encoding")
	}
	// The callback writer percent-encodes string leaves before framing.
	wire, err := omadalink.EncodeResponseStrings(s.Passthrough(json.RawMessage(detectionRead)))
	if err != nil || strings.Contains(string(wire), `["0000-2400"]`) || !strings.Contains(string(wire), `"monday":"%5b%220000-2400%22%5d"`) {
		t.Fatal("native wire did not percent-encode the schedule string like the donor")
	}
	_, tamper := request(t, s, path, `{"method":"get","tamper_detection":{"name":["tamper_det","tamper_notif_list"]}}`)
	tamperDet := metadataObject(t, metadataObject(t, tamper["tamper_detection"])["tamper_det"])
	if tamperDet["enabled"] != "on" || tamperDet["digital_sensitivity"] != "50" {
		t.Fatal("virtual tamper detection must pass source alarms by default")
	}
}

func TestVirtualDetectionWritesUpdateStateWithoutTouchingOtherModules(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	for _, body := range []string{
		`{"method":"set","motion_detection":{"motion_det":{"enabled":"off","sensitivity":"high"}}}`,
		`{"method":"set","motion_detection":{"arming_schedule":{"monday":"%5b%220800-1800%22%5d"}}}`,
		`{"method":"do","motion_detection":{"add_polygon_regions":{"polygon_region_info":[{"id":1,"points_num":"4","points_x":[1,2,3,4],"points_y":[5,6,7,8],"people_enabled":"on"}]}}}`,
		`{"method":"set","tamper_detection":{"tamper_det":{"enabled":"on"}}}`,
	} {
		code, response := request(t, s, path, body)
		if code != http.StatusOK || !reflect.DeepEqual(response, map[string]any{"error_code": float64(0)}) {
			t.Fatalf("captured detection write was rejected: %s", body)
		}
	}
	_, response := request(t, s, path, detectionRead)
	motion := metadataObject(t, response["motion_detection"])
	det := metadataObject(t, motion["motion_det"])
	if det["enabled"] != "off" || det["sensitivity"] != "high" || det["people_enabled"] != "on" {
		t.Fatal("set did not merge leaves into the existing section")
	}
	if metadataObject(t, motion["arming_schedule"])["monday"] != `["0800-1800"]` {
		t.Fatal("percent-encoded HTTPS schedule value was not decoded once")
	}
	rows := motion["polygon_region_info"].([]any)
	row := metadataObject(t, metadataObject(t, rows[0])["polygon_region_info_1"])
	if len(rows) != 1 || row["people_enabled"] != "on" || row["points_x"].([]any)[0] != float64(1) {
		t.Fatal("region operation did not replace the table")
	}
	_, tamper := request(t, s, path, `{"method":"get","tamper_detection":{"name":"tamper_det"}}`)
	if metadataObject(t, metadataObject(t, tamper["tamper_detection"])["tamper_det"])["enabled"] != "on" {
		t.Fatal("tamper write was lost")
	}
	for _, body := range []string{
		`{"method":"set","motion_detection":{"unknown_section":{"enabled":"on"}}}`,
		`{"method":"set","motion_detection":{"motion_det":{"enabled":{"nested":true}}}}`,
		`{"method":"set","motion_detection":{"motion_det":{"enabled":"on"}},"tamper_detection":{"tamper_det":{"enabled":"on"}}}`,
		`{"method":"do","motion_detection":{"reboot":{"polygon_region_info":[]}}}`,
		`{"method":"do","motion_detection":{"delete_polygon_regions":{"polygon_region_info":[{"id":1}]}}}`,
		`{"method":"set","regionentrance_detection":{"detection":{"enabled":"on"}}}`,
	} {
		_, response := request(t, s, path, body)
		if response["error_code"] != float64(unsupportedCode) {
			t.Fatalf("invalid or unsupported detection write was accepted: %s", body)
		}
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"do","motion_detection":{"add_polygon_regions":{"polygon_region_info":[]}}}`)), &native); err != nil || native["error_code"] != float64(0) {
		t.Fatal("native empty region list was rejected")
	}
	_, response = request(t, s, path, detectionRead)
	if rows := metadataObject(t, response["motion_detection"])["polygon_region_info"].([]any); len(rows) != 0 {
		t.Fatal("an empty region list did not replace the table")
	}
}
