package cameraevents

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var received = time.Date(2026, 10, 15, 13, 47, 0, 0, time.UTC)

func TestIntelligentIsUnknownUntilExactlyScopedMapping(t *testing.T) {
	payload := `{"method":"client.notifyEventStream","session":123,"params":{"eventList":[{"Code":"Intelligent","Action":"Start","Index":0,"Data":{"UTC":1792075200,"LocaleTime":"2026-10-15 16:20:00","event":"336700","outputData":{}}},{"Code":"Intelligent","Action":"Stop","Index":1,"Data":{"event":"336700"}}]}}`
	events, err := Normalize("imou-30-10", received, payload, nil)
	if err != nil || len(events) != 2 {
		t.Fatalf("normalization failed: %v", err)
	}
	if events[0].Class != "unknown" || events[0].Discriminator != "336700" || events[0].DeviceUTC != "1792075200" || events[0].SourceIndex != 0 || events[1].SourceIndex != 1 {
		t.Fatalf("source or native provenance was changed: %#v", events)
	}
	mapping := Mapping{DeviceID: "imou-30-10", SourceIndex: 0, Code: "Intelligent", Discriminator: "336700", Class: "human"}
	events, err = Normalize("imou-30-10", received, payload, []Mapping{mapping})
	if err != nil || events[0].Class != "human" || events[0].Evidence != "operator_correlated" || events[1].Class != "unknown" {
		t.Fatalf("mapping did not remain source scoped: %#v, %v", events, err)
	}
	events, err = Normalize("different-camera", received, payload, []Mapping{mapping})
	if err != nil || events[0].Class != "unknown" {
		t.Fatalf("mapping leaked to another camera: %#v, %v", events, err)
	}
	events, err = Normalize("imou-30-10", received, strings.ReplaceAll(payload, "336700", "336701"), []Mapping{mapping})
	if err != nil || events[0].Class != "unknown" {
		t.Fatalf("mapping leaked to another discriminator: %#v, %v", events, err)
	}
}

func TestNativeCodesAndCGIFields(t *testing.T) {
	for _, test := range []struct {
		code, kind, class string
	}{{"SmartMotionHuman", "smart_motion", "human"}, {"SmartMotionVehicle", "smart_motion", "vehicle"}, {"VideoMotion", "motion", "unknown"}, {"NeverSeenEvent", "unknown", "unknown"}} {
		t.Run(test.code, func(t *testing.T) {
			payload := map[string]any{"Code": test.code, "action": "Start", "index": "0", "data": map[string]any{"RealUTC": json.Number("1792075200.125"), "RuleID": "4", "object": []any{map[string]any{"ObjectType": "Vehicle", "VehicleID": 55}}}}
			events, err := Normalize("camera", received, payload, nil)
			if err != nil || len(events) != 1 {
				t.Fatalf("normalization failed: %v", err)
			}
			event := events[0]
			if event.Code != test.code || event.Kind != test.kind || event.Class != test.class || event.DeviceRealUTC != "1792075200.125" || event.RuleIDs["RuleID"] != "4" || len(event.ObjectTypes) != 1 || event.ObjectTypes[0] != "Vehicle" {
				t.Fatalf("native fields were lost or guessed: %#v", event)
			}
			if !event.ReceivedUTC.Equal(received) || event.ReceivedUTC.Location() != time.UTC {
				t.Fatal("receive time was altered")
			}
		})
	}
}

func TestIVSObjectClassificationAndSourceProvenance(t *testing.T) {
	for _, test := range []struct {
		name, code, data, kind, class, evidence string
		classes, objectTypes                    []string
	}{
		{"nested human", "CrossLineDetection", `{"Object":{"ObjectType":"Human"}}`, "line_crossing", "human", "native_object", []string{"human"}, []string{"Human"}},
		{"object list vehicle", "CrossRegionDetection", `{"object":[{"ObjectType":"Vehicle"}]}`, "intrusion", "vehicle", "native_object", []string{"vehicle"}, []string{"Vehicle"}},
		{"top-level pet", "CrossRegionDetection", `{"ObjectType":"Pet"}`, "intrusion", "pet", "native_object", []string{"pet"}, []string{"Pet"}},
		{"explicit animal", "CrossLineDetection", `{"Object":{"ObjectType":"Animal"}}`, "line_crossing", "pet", "native_object", []string{"pet"}, []string{"Animal"}},
		{"class field", "CrossLineDetection", `{"Class":"human"}`, "line_crossing", "human", "native_object", []string{"human"}, []string{"human"}},
		{"multiple classes", "CrossLineDetection", `{"ObjectTypes":["Pet","Vehicle","Human","Animal"],"Object":{"ObjectType":"Vehicle"},"object":[{"Class":"Human"}]}`, "line_crossing", "unknown", "native_object", []string{"human", "vehicle", "pet"}, []string{"Pet", "Vehicle", "Human", "Animal"}},
		{"deduplicated case variants", "CrossRegionDetection", `{"ObjectTypes":["Human","human","Human"]}`, "intrusion", "human", "native_object", []string{"human"}, []string{"Human", "human"}},
		{"unclassified IVS", "CrossRegionDetection", `{}`, "intrusion", "unknown", "native_code", nil, nil},
		{"unknown object type", "CrossLineDetection", `{"ObjectType":"UnrecognizedObject"}`, "line_crossing", "unknown", "native_code", nil, []string{"UnrecognizedObject"}},
		{"unknown alongside explicit", "CrossLineDetection", `{"ObjectTypes":["Unknown","Human"]}`, "line_crossing", "human", "native_object", []string{"human"}, []string{"Unknown", "Human"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := `{"Code":"` + test.code + `","Action":"Pulse","Index":1,"Data":` + test.data + `}`
			events, err := Normalize("camera", received, payload, nil)
			if err != nil || len(events) != 1 {
				t.Fatalf("normalize IVS event: %v", err)
			}
			event := events[0]
			if event.Kind != test.kind || event.Class != test.class || event.Evidence != test.evidence || !reflect.DeepEqual(event.Classes, test.classes) || !reflect.DeepEqual(event.ObjectTypes, test.objectTypes) {
				t.Fatalf("classification differs: %#v", event)
			}
			if event.SourceIndex != 1 || event.Action != "Pulse" || event.DeviceID != "camera" {
				t.Fatalf("source or action was changed: %#v", event)
			}
		})
	}
}

func TestIVSDoesNotGuessFromObjectIDsOrConfigurationFlags(t *testing.T) {
	for _, data := range []string{
		`{"Object":{"HumanID":12,"Type":"Human"}}`,
		`{"ObjectType":1,"ObjectTypes":{"Human":true,"Vehicle":true}}`,
		`{"outputData":{"Object":{"ObjectType":"Human"}}}`,
		`{"ObjectType":"HumanLike","Class":"Face"}`,
		`{"Object":{"ObjectType":"Human\n"}}`,
	} {
		events, err := Normalize("camera", received, `{"Code":"CrossLineDetection","Action":"Start","Index":0,"Data":`+data+`}`, nil)
		if err != nil || len(events) != 1 {
			t.Fatalf("normalize unclassified IVS: %v", err)
		}
		if events[0].Class != "unknown" || len(events[0].Classes) != 0 || events[0].Evidence != "native_code" {
			t.Fatalf("inferred class without explicit object type: %#v", events[0])
		}
	}
}

func TestClassificationDoesNotOverrideSmartCodesOrIntelligentScope(t *testing.T) {
	for _, test := range []struct{ code, class, evidence string }{
		{"SmartMotionHuman", "human", "native_code"},
		{"SmartMotionVehicle", "vehicle", "native_code"},
		{"Intelligent", "unknown", "unclassified"},
		{"NeverSeenEvent", "unknown", "unclassified"},
		{"VideoBlind", "unknown", "native_code"},
	} {
		events, err := Normalize("camera", received, `{"Code":"`+test.code+`","Action":"Start","Index":0,"Data":{"Object":{"ObjectType":"Human"},"ObjectTypes":["Pet","Vehicle"]}}`, nil)
		if err != nil || len(events) != 1 {
			t.Fatalf("normalize %s: %v", test.code, err)
		}
		if events[0].Class != test.class || events[0].Evidence != test.evidence || len(events[0].Classes) != 0 {
			t.Fatalf("object type overrode native code or unclassified scope: %#v", events[0])
		}
		if test.code == "VideoBlind" && events[0].Kind != "tamper" {
			t.Fatalf("VideoBlind did not normalize to tamper: %#v", events[0])
		}
	}
}

func TestIVSStopWithoutObjectClassificationRemainsUnclassified(t *testing.T) {
	events, err := Normalize("camera", received, `{"Code":"CrossRegionDetection","Action":"Stop","Index":0,"Data":{"RuleID":2}}`, nil)
	if err != nil || len(events) != 1 {
		t.Fatalf("normalize sparse stop: %v", err)
	}
	if events[0].Action != "Stop" || events[0].Kind != "intrusion" || events[0].Class != "unknown" || len(events[0].Classes) != 0 || events[0].RuleIDs["RuleID"] != json.Number("2") {
		t.Fatalf("sparse stop provenance was altered: %#v", events[0])
	}
}

func TestCollectorResponseCopiesNeverBecomeEvents(t *testing.T) {
	for _, payload := range []string{
		`{"kind":"response","data":{"Code":"VideoMotion","Action":"Start","Index":0}}`,
		`{"method":"eventManager.attach","params":{"eventList":[{"Code":"VideoMotion","Action":"Start","Index":0}]},"result":true}`,
		`{"response":{"params":{"eventList":[{"Code":"VideoMotion","Action":"Start","Index":0}]}}}`,
	} {
		events, err := Normalize("camera", received, payload, nil)
		if err != nil || len(events) != 0 {
			t.Fatalf("response copy normalized as detection: %v", err)
		}
	}
	events, err := Normalize("camera", received, `{"kind":"event","device_id":"camera","data":{"Code":"VideoMotion","Action":"Start","Index":0}}`, nil)
	if err != nil || len(events) != 1 {
		t.Fatalf("collector event was ignored: %v", err)
	}
	if _, err := Normalize("other-camera", received, `{"kind":"event","device_id":"camera","data":{"Code":"VideoMotion","Action":"Start","Index":0}}`, nil); err == nil {
		t.Fatal("mismatched collector device accepted")
	}
}

func TestMissingSourceStaysUnknownAndEventsAreNotDeduplicated(t *testing.T) {
	payload := `{"method":"client.notifyEventStream","params":{"eventList":[{"Code":"VideoMotion","Action":"Start"},{"Code":"VideoMotion","Action":"Start"}]}}`
	events, err := Normalize("camera", received, payload, nil)
	if err != nil || len(events) != 2 || events[0].SourceIndex != -1 || events[1].SourceIndex != -1 {
		t.Fatalf("missing source became zero or entries were merged: %#v %v", events, err)
	}
}

func TestNoAuthSessionOrRawPayloadLeak(t *testing.T) {
	payload := map[string]any{"method": "client.notifyEventStream", "session": "SECRET_SESSION", "params": map[string]any{"eventList": []any{map[string]any{"Code": "Intelligent", "Action": "Start", "Index": 0, "Data": map[string]any{"event": map[string]any{"subtype": "unmapped", "access_token": "SECRET_TOKEN", "nested": map[string]any{"password": "SECRET_PASSWORD", "id": json.Number("9007199254740993")}}, "outputData": map[string]any{"password": "SECRET_PASSWORD"}}}}}}
	events, err := Normalize("camera", received, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(events)
	if err != nil || strings.Contains(string(encoded), "SECRET_") || strings.Contains(string(encoded), "outputData") || !strings.Contains(string(encoded), "9007199254740993") {
		t.Fatal("selected fields lost precision or exposed excluded data")
	}
	// Output must not alias mutable input structures.
	events[0].Discriminator.(map[string]any)["subtype"] = "changed"
	entries := payload["params"].(map[string]any)["eventList"].([]any)
	original := entries[0].(map[string]any)["Data"].(map[string]any)["event"].(map[string]any)
	if original["subtype"] != "unmapped" {
		t.Fatal("normalization exposed mutable input alias")
	}
}

func TestBoundsAndMalformedInputFailWithoutEchoingValues(t *testing.T) {
	deep := map[string]any{}
	deep["cycle"] = deep
	for _, payload := range []any{
		strings.Repeat("SECRET", maxPayloadBytes/6+1),
		`{"Code":"SECRET","Action":"Start","Index":-1}`,
		`{"Code":"SECRET","Action":"Start","Index":0.5}`,
		`{"Code":"SECRET","Action":"Start","Data":{"UTC":"not-a-time"}}`,
		`{"Code":"SECRET","Action":"Start"} {}`,
		`{"method":"client.notifyEventStream","params":{"eventList":[{"Code":"VideoMotion","Action":"Start"},false]}}`,
		map[string]any{"Code": "SECRET", "Action": "Start", "Data": map[string]any{"event": strings.Repeat("a", 4097)}},
		deep,
	} {
		events, err := Normalize("camera", received, payload, nil)
		if err == nil || len(events) != 0 || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("invalid input accepted or echoed: %v", err)
		}
	}
	mapping := Mapping{DeviceID: "camera", SourceIndex: 0, Code: "Intelligent", Discriminator: "336700", Class: "human"}
	if _, err := Normalize("camera", received, `{}`, []Mapping{mapping, mapping}); err == nil {
		t.Fatal("ambiguous duplicate mappings accepted")
	}
}

func FuzzNormalize(f *testing.F) {
	f.Add([]byte(`{"Code":"VideoMotion","Action":"Start","Index":0}`))
	f.Add([]byte(`{"method":"client.notifyEventStream","params":{"eventList":[]}}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		events, err := Normalize("camera", received, payload, nil)
		if err != nil {
			return
		}
		if _, err := json.Marshal(events); err != nil {
			t.Fatal("normalized output cannot be encoded")
		}
	})
}
