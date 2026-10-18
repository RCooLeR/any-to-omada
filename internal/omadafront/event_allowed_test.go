package omadafront

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func TestEventAllowedFollowsVirtualDetectionSettings(t *testing.T) {
	s := testServer(t, nil)
	path := login(t, s)
	for eventType, want := range map[omadalink.EventType]bool{
		omadalink.EventMotion: true, omadalink.EventHumanMotion: true,
		omadalink.EventTamper:    true,
		omadalink.EventIntrusion: true, omadalink.EventHumanIntrusion: true, omadalink.EventVehicleIntrusion: true, omadalink.EventPetIntrusion: true,
		omadalink.EventLineCrossing: true, omadalink.EventHumanLine: true, omadalink.EventVehicleLine: true, omadalink.EventPetLine: true,
		omadalink.EventHuman: false,
	} {
		if s.EventAllowed(eventType) != want {
			t.Fatalf("default settings: event type %d allowed=%v", eventType, !want)
		}
	}
	set := func(body string) {
		t.Helper()
		code, response := request(t, s, path, body)
		if code != http.StatusOK || !reflect.DeepEqual(response, map[string]any{"error_code": float64(0)}) {
			t.Fatalf("settings write rejected: %s", body)
		}
	}
	set(`{"method":"set","motion_detection":{"motion_det":{"vehicle_enabled":"off"}}}`)
	if !s.EventAllowed(omadalink.EventMotion) || !s.EventAllowed(omadalink.EventHumanMotion) || s.EventAllowed(omadalink.EventVehicleMotion) {
		t.Fatal("motion gate does not follow motion_det class flags")
	}
	set(`{"method":"set","motion_detection":{"motion_det":{"enabled":"off"}}}`)
	if s.EventAllowed(omadalink.EventMotion) {
		t.Fatal("disabled motion detection still allows motion starts")
	}
	set(`{"method":"do","intrusion_detection":{"add_regions":{"region_info":[{"id":1,"people_enabled":"on","vehicle_enabled":"on","pet_enabled":"off"}]}}}`)
	if !s.EventAllowed(omadalink.EventVehicleIntrusion) || s.EventAllowed(omadalink.EventPetIntrusion) {
		t.Fatal("intrusion gate does not follow region class flags")
	}
	set(`{"method":"set","intrusion_detection":{"detection":{"enabled":"off"}}}`)
	if s.EventAllowed(omadalink.EventHumanIntrusion) {
		t.Fatal("disabled intrusion detection still allows human intrusion")
	}
	set(`{"method":"set","tamper_detection":{"tamper_det":{"enabled":"off"}}}`)
	if s.EventAllowed(omadalink.EventTamper) || s.EventAllowed(omadalink.EventIntrusion) {
		t.Fatal("disabled tamper or unclassified intrusion still passes")
	}
}

func TestIntrusionGateUsesTheAdvertisedRegionFormat(t *testing.T) {
	for _, tc := range []struct {
		name, operation, table, inactiveOperation, inactiveTable string
		observed                                                 bool
	}{
		{"polygon", "add_polygon_regions", "polygon_region_info", "add_regions", "region_info", true},
		{"rectangle", "add_regions", "region_info", "add_polygon_regions", "polygon_region_info", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := func(cfg *Config) { cfg.Compatibility.ObservedModuleSpec = tc.observed }
			s, other := testServer(t, options), testServer(t, options)
			path := login(t, s)
			writeRegions := func(operation, table string, rows []any) {
				t.Helper()
				body, err := json.Marshal(map[string]any{"method": "do", "intrusion_detection": map[string]any{operation: map[string]any{table: rows}}})
				if err != nil {
					t.Fatal(err)
				}
				code, response := request(t, s, path, string(body))
				if code != http.StatusOK || response["error_code"] != float64(0) {
					t.Fatal("region write rejected")
				}
			}
			writeRegions(tc.operation, tc.table, []any{map[string]any{"id": 1, "people_enabled": "off", "vehicle_enabled": "on"}})
			if s.EventAllowed(omadalink.EventHumanIntrusion) || !s.EventAllowed(omadalink.EventVehicleIntrusion) {
				t.Fatal("inactive default region overrode the active region's class filter")
			}
			writeRegions(tc.inactiveOperation, tc.inactiveTable, []any{map[string]any{"id": 1, "people_enabled": "on", "pet_enabled": "on"}})
			if s.EventAllowed(omadalink.EventHumanIntrusion) || s.EventAllowed(omadalink.EventPetIntrusion) {
				t.Fatal("inactive region format changed the event gate")
			}
			writeRegions(tc.operation, tc.table, []any{})
			if s.EventAllowed(omadalink.EventIntrusion) || s.EventAllowed(omadalink.EventHumanIntrusion) || s.EventAllowed(omadalink.EventVehicleIntrusion) || s.EventAllowed(omadalink.EventPetIntrusion) {
				t.Fatal("cleared active regions still allow intrusion starts")
			}
			if !other.EventAllowed(omadalink.EventHumanIntrusion) || !other.EventAllowed(omadalink.EventVehicleIntrusion) || !other.EventAllowed(omadalink.EventPetIntrusion) {
				t.Fatal("region writes changed another camera's detection state")
			}
		})
	}
}
