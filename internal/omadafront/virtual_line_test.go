package omadafront

import (
	"encoding/json"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const lineRead = `{"method":"get","linecrossing_detection":{"version":"1","name":["detection","notify_list","arming_schedule"],"table":["polyline_region_info","region_info"]}}`

func TestLineDetectionReadsAndWritesShareBothTransports(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	_, response := request(t, s, path, lineRead)
	if response["error_code"] != float64(0) {
		t.Fatal("observed line detection selector was rejected")
	}
	line := metadataObject(t, response["linecrossing_detection"])
	if metadataObject(t, line["detection"])["enabled"] != "on" || metadataObject(t, line["notify_list"])["record_enabled"] != "on" ||
		metadataObject(t, line["arming_schedule"])["friday"] != `["0000-2400"]` {
		t.Fatal("virtual line detection defaults must pass source alarms and record all day")
	}
	for _, table := range []string{"polyline_region_info", "region_info"} {
		rows := line[table].([]any)
		if len(rows) != 1 {
			t.Fatal("virtual line geometry is missing")
		}
		region := metadataObject(t, metadataObject(t, rows[0])[table+"_1"])
		if region["direction"] != "both" || region["people_enabled"] != "on" || region["vehicle_enabled"] != "on" || region["pet_enabled"] != "on" {
			t.Fatal("line region does not pass every translated class")
		}
	}
	var native map[string]any
	if err := json.Unmarshal(s.Passthrough(json.RawMessage(`{"method":"set","linecrossing_detection":{"detection":{"enabled":"off"}}}`)), &native); err != nil || native["error_code"] != float64(0) {
		t.Fatal("native line settings write was rejected")
	}
	_, response = request(t, s, path, lineRead)
	if metadataObject(t, metadataObject(t, response["linecrossing_detection"])["detection"])["enabled"] != "off" || s.EventAllowed(omadalink.EventLineCrossing) {
		t.Fatal("native write was not reflected by HTTPS and the alarm gate")
	}
}

func TestLineGateUsesSelectedRegionFormatAndClass(t *testing.T) {
	for _, tc := range []struct {
		name, operation, table, inactiveOperation, inactiveTable string
		observed                                                 bool
	}{
		{"polyline", "add_polyline_regions", "polyline_region_info", "add_regions", "region_info", true},
		{"legacy", "add_regions", "region_info", "add_polyline_regions", "polyline_region_info", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := func(cfg *Config) { cfg.Compatibility.ObservedModuleSpec = tc.observed }
			s, other := testServer(t, options), testServer(t, options)
			writeRegions := func(operation, table string, rows []any) {
				t.Helper()
				body, err := json.Marshal(map[string]any{"method": "do", "linecrossing_detection": map[string]any{operation: map[string]any{table: rows}}})
				if err != nil {
					t.Fatal(err)
				}
				var response map[string]any
				if err := json.Unmarshal(s.Passthrough(body), &response); err != nil || response["error_code"] != float64(0) {
					t.Fatal("line region operation rejected")
				}
			}
			writeRegions(tc.operation, tc.table, []any{map[string]any{"id": 1, "people_enabled": "off", "vehicle_enabled": "on", "pet_enabled": "off"}})
			if !s.EventAllowed(omadalink.EventLineCrossing) || s.EventAllowed(omadalink.EventHumanLine) || !s.EventAllowed(omadalink.EventVehicleLine) || s.EventAllowed(omadalink.EventPetLine) {
				t.Fatal("line event gate ignores source classification or selected region")
			}
			writeRegions(tc.inactiveOperation, tc.inactiveTable, []any{map[string]any{"id": 1, "people_enabled": "on", "pet_enabled": "on"}})
			if s.EventAllowed(omadalink.EventHumanLine) || s.EventAllowed(omadalink.EventPetLine) {
				t.Fatal("inactive line region format overrode the configured class filter")
			}
			writeRegions(tc.operation, tc.table, []any{map[string]any{"id": 1, "people_enabled": "off", "vehicle_enabled": "off", "pet_enabled": "on"}})
			if !s.EventAllowed(omadalink.EventPetLine) || s.EventAllowed(omadalink.EventVehicleLine) {
				t.Fatal("line class filter did not update")
			}
			writeRegions(tc.operation, tc.table, []any{})
			for _, eventType := range []omadalink.EventType{omadalink.EventLineCrossing, omadalink.EventHumanLine, omadalink.EventVehicleLine, omadalink.EventPetLine} {
				if s.EventAllowed(eventType) || !other.EventAllowed(eventType) {
					t.Fatal("empty line rules or camera isolation failed")
				}
			}
			if !s.EventAllowed(omadalink.EventIntrusion) || !s.EventAllowed(omadalink.EventTamper) {
				t.Fatal("line writes changed unrelated alarm gates")
			}
		})
	}
}
