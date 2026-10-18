package app

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

var translationTime = time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)

func normalizedTranslationEvent(t *testing.T, code, action string, index int, data map[string]any, mappings ...cameraevents.Mapping) cameraevents.Event {
	t.Helper()
	events, err := cameraevents.Normalize("camera", translationTime, map[string]any{
		"Code": code, "Action": action, "Index": index, "Data": data,
	}, mappings)
	if err != nil || len(events) != 1 {
		t.Fatalf("normalize source notification: count=%d error=%v", len(events), err)
	}
	return events[0]
}

func assertTranslatedEvents(t *testing.T, wires []omadalink.Event, status uint8, types ...omadalink.EventType) {
	t.Helper()
	if len(wires) != len(types) {
		t.Fatalf("wire notification count=%d, want %d: %#v", len(wires), len(types), wires)
	}
	for index, eventType := range types {
		if wires[index].Type != eventType || wires[index].Status != status || wires[index].RegionID != 0 {
			t.Fatalf("notification %d=%#v, want type=%d status=%d without invented region", index, wires[index], eventType, status)
		}
	}
}

func TestTranslationNormalizesSourceNotificationsToOmadaEvents(t *testing.T) {
	for _, test := range []struct {
		name, code string
		data       map[string]any
		types      []omadalink.EventType
	}{
		{"motion", "VideoMotion", nil, []omadalink.EventType{omadalink.EventMotion}},
		{"human motion", "SmartMotionHuman", nil, []omadalink.EventType{omadalink.EventHumanMotion}},
		{"vehicle motion", "SmartMotionVehicle", nil, []omadalink.EventType{omadalink.EventVehicleMotion}},
		{"pet motion", "SmartMotionPet", nil, []omadalink.EventType{omadalink.EventPetMotion}},
		{"line", "CrossLineDetection", nil, []omadalink.EventType{omadalink.EventLineCrossing}},
		{"intrusion", "CrossRegionDetection", nil, []omadalink.EventType{omadalink.EventIntrusion}},
		{"human line", "CrossLineDetection", map[string]any{"Object": map[string]any{"ObjectType": "Human"}}, []omadalink.EventType{omadalink.EventHumanLine}},
		{"vehicle line", "CrossLineDetection", map[string]any{"object": []any{map[string]any{"ObjectType": "Vehicle"}}}, []omadalink.EventType{omadalink.EventVehicleLine}},
		{"pet line", "CrossLineDetection", map[string]any{"ObjectType": "Animal"}, []omadalink.EventType{omadalink.EventPetLine}},
		{"human intrusion", "CrossRegionDetection", map[string]any{"Class": "Human"}, []omadalink.EventType{omadalink.EventHumanIntrusion}},
		{"vehicle intrusion", "CrossRegionDetection", map[string]any{"ObjectType": "Vehicle"}, []omadalink.EventType{omadalink.EventVehicleIntrusion}},
		{"pet intrusion", "CrossRegionDetection", map[string]any{"ObjectTypes": []any{"Pet"}}, []omadalink.EventType{omadalink.EventPetIntrusion}},
		{"mixed line", "CrossLineDetection", map[string]any{"ObjectTypes": []any{"Animal", "Vehicle", "Human", "Pet", "Human"}}, []omadalink.EventType{omadalink.EventHumanLine, omadalink.EventVehicleLine, omadalink.EventPetLine}},
		{"mixed intrusion", "CrossRegionDetection", map[string]any{"ObjectTypes": []any{"Vehicle", "Animal", "Human"}}, []omadalink.EventType{omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion, omadalink.EventPetIntrusion}},
		{"unknown IVS class", "CrossLineDetection", map[string]any{"ObjectType": "Unknown"}, []omadalink.EventType{omadalink.EventLineCrossing}},
		{"tamper", "VideoBlind", nil, []omadalink.EventType{omadalink.EventTamper}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, action := range []string{"Start", "Stop", "Pulse"} {
				event := normalizedTranslationEvent(t, test.code, action, 0, test.data)
				wires, ok := nativeEvents(event)
				if !ok {
					t.Fatalf("supported %s/%s not translated", test.code, action)
				}
				status := uint8(1)
				if action == "Stop" {
					status = 3
				}
				assertTranslatedEvents(t, wires, status, test.types...)
			}
		})
	}
}

func TestTranslationRequiresScopedIntelligentEvidence(t *testing.T) {
	for _, test := range []struct {
		class     string
		eventType omadalink.EventType
	}{
		{"human", omadalink.EventHumanIntrusion},
		{"vehicle", omadalink.EventVehicleIntrusion},
		{"pet", omadalink.EventPetIntrusion},
	} {
		mapping := cameraevents.Mapping{DeviceID: "camera", SourceIndex: 0, Code: "Intelligent", Discriminator: "336700", Class: test.class}
		data := map[string]any{"event": "336700"}
		event := normalizedTranslationEvent(t, "Intelligent", "Start", 0, data, mapping)
		wires, ok := nativeEvents(event)
		if !ok {
			t.Fatalf("scoped %s Intelligent mapping was lost", test.class)
		}
		assertTranslatedEvents(t, wires, 1, test.eventType)
		for _, unmapped := range []cameraevents.Event{
			normalizedTranslationEvent(t, "Intelligent", "Start", 1, data, mapping),
			normalizedTranslationEvent(t, "Intelligent", "Start", 0, map[string]any{"event": "336701"}, mapping),
			normalizedTranslationEvent(t, "Intelligent", "Start", 0, data),
		} {
			if got, ok := nativeEvents(unmapped); ok || len(got) != 0 {
				t.Fatalf("Intelligent classification escaped its source scope: %#v", got)
			}
		}
	}
}

func TestTranslationKeepsUnknownAndDiagnosticEventsUnmapped(t *testing.T) {
	for _, code := range []string{"NeverSeenEvent", "RtspSessionDisconnect", "InterVideoAccess", "VideoMotionInfo", "LeftDetection", "MoveDetection"} {
		for _, action := range []string{"Start", "Stop", "Pulse", "State"} {
			event := normalizedTranslationEvent(t, code, action, 0, map[string]any{"ObjectType": "Human"})
			if wires, ok := nativeEvents(event); ok || len(wires) != 0 {
				t.Fatalf("diagnostic or unsupported %s/%s became detection: %#v", code, action, wires)
			}
		}
	}
	for _, action := range []string{"State", "UnrecognizedAction"} {
		if wires, ok := nativeEvents(normalizedTranslationEvent(t, "VideoMotion", action, 0, nil)); ok || len(wires) != 0 {
			t.Fatalf("unsupported motion action became detection: %#v", wires)
		}
	}
}

func TestTranslationPulseExpiresWithMatchingStop(t *testing.T) {
	tracker := make(alarmTracker)
	pulse := normalizedTranslationEvent(t, "CrossRegionDetection", "Pulse", 0, map[string]any{"ObjectTypes": []any{"Human", "Vehicle"}})
	wires, outcome, suppressed := tracker.apply(pulse, translationTime, nil)
	if outcome != "queued" || suppressed != 0 {
		t.Fatalf("pulse outcome=%s suppressed=%d", outcome, suppressed)
	}
	assertTranslatedEvents(t, wires, 1, omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion)
	assertTranslatedEvents(t, tracker.expire(translationTime.Add(translatedPulseDuration-time.Nanosecond)), 3)
	assertTranslatedEvents(t, tracker.expire(translationTime.Add(translatedPulseDuration)), 3, omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion)
	assertTranslatedEvents(t, tracker.expire(translationTime.Add(2*translatedPulseDuration)), 3)
	if len(tracker) != 0 || tracker.intrusionStart() != 0 {
		t.Fatal("expired pulse retained active alarm state")
	}
}

func TestTranslationPulseRefreshExtendsOnlyPulseInterval(t *testing.T) {
	tracker := make(alarmTracker)
	pulse := normalizedTranslationEvent(t, "VideoMotion", "Pulse", 0, nil)
	tracker.apply(pulse, translationTime, nil)
	refresh := translationTime.Add(translatedPulseDuration / 2)
	tracker.apply(pulse, refresh, nil)
	assertTranslatedEvents(t, tracker.expire(translationTime.Add(translatedPulseDuration)), 3)
	assertTranslatedEvents(t, tracker.expire(refresh.Add(translatedPulseDuration)), 3, omadalink.EventMotion)

	for _, startFirst := range []bool{true, false} {
		tracker = make(alarmTracker)
		start := pulse
		start.Action = "Start"
		if startFirst {
			tracker.apply(start, translationTime, nil)
			tracker.apply(pulse, refresh, nil)
		} else {
			tracker.apply(pulse, translationTime, nil)
			tracker.apply(start, refresh, nil)
		}
		assertTranslatedEvents(t, tracker.expire(refresh.Add(10*translatedPulseDuration)), 3)
		if !tracker.has(omadalink.EventMotion) {
			t.Fatal("pulse expiry shortened a source-controlled Start interval")
		}
		stop := start
		stop.Action = "Stop"
		wires, outcome, _ := tracker.apply(stop, refresh.Add(11*translatedPulseDuration), nil)
		if outcome != "queued" {
			t.Fatalf("source-controlled Stop outcome=%s", outcome)
		}
		assertTranslatedEvents(t, wires, 3, omadalink.EventMotion)
	}
}

func TestTranslationSparseStopReusesOnlyMatchingSourceRuleClasses(t *testing.T) {
	tracker := make(alarmTracker)
	start := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0, map[string]any{"RuleID": 7, "ObjectTypes": []any{"Human", "Vehicle"}})
	tracker.apply(start, translationTime, nil)

	otherRule := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0, map[string]any{"RuleID": 8, "ObjectType": "Human"})
	tracker.apply(otherRule, translationTime.Add(time.Millisecond), nil)
	otherSource := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 1, map[string]any{"RuleID": 7, "ObjectType": "Vehicle"})
	tracker.apply(otherSource, translationTime.Add(2*time.Millisecond), nil)

	sparseStop := normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 0, map[string]any{"RuleID": 7})
	wires, outcome, _ := tracker.apply(sparseStop, translationTime.Add(time.Second), nil)
	if outcome != "queued" {
		t.Fatalf("sparse Stop outcome=%s", outcome)
	}
	assertTranslatedEvents(t, wires, 3)
	if len(tracker) != 2 || !tracker.has(omadalink.EventHumanIntrusion) || !tracker.has(omadalink.EventVehicleIntrusion) {
		t.Fatal("sparse Stop closed an overlapping source or rule")
	}
	sparseStop.RuleIDs["RuleID"] = 8
	wires, _, _ = tracker.apply(sparseStop, translationTime.Add(2*time.Second), nil)
	assertTranslatedEvents(t, wires, 3, omadalink.EventHumanIntrusion)
	sparseStop.SourceIndex = 1
	sparseStop.RuleIDs["RuleID"] = 7
	wires, _, _ = tracker.apply(sparseStop, translationTime.Add(3*time.Second), nil)
	assertTranslatedEvents(t, wires, 3, omadalink.EventVehicleIntrusion)
	if len(tracker) != 0 {
		t.Fatal("matched source Stops left active tracker state")
	}
}

func TestTranslationPulseDoesNotCloseOverlappingRuleStart(t *testing.T) {
	tracker := make(alarmTracker)
	start := normalizedTranslationEvent(t, "CrossLineDetection", "Start", 0, map[string]any{"RuleID": 1, "ObjectType": "Human"})
	pulse := normalizedTranslationEvent(t, "CrossLineDetection", "Pulse", 0, map[string]any{"RuleID": 2, "ObjectType": "Human"})
	tracker.apply(start, translationTime, nil)
	tracker.apply(pulse, translationTime, nil)
	assertTranslatedEvents(t, tracker.expire(translationTime.Add(translatedPulseDuration)), 3)
	if len(tracker) != 1 || !tracker.has(omadalink.EventHumanLine) {
		t.Fatal("pulse expiry closed overlapping rule's continuous alarm")
	}
	start.Action = "Stop"
	wires, _, _ := tracker.apply(start, translationTime.Add(2*translatedPulseDuration), nil)
	assertTranslatedEvents(t, wires, 3, omadalink.EventHumanLine)
}

func TestTranslationTrackerBoundAndCandidateIsolation(t *testing.T) {
	tracker := make(alarmTracker)
	for rule := 0; rule < maxTrackedAlarmKeys; rule++ {
		event := normalizedTranslationEvent(t, "CrossLineDetection", "Start", 0, map[string]any{"RuleID": rule})
		if _, outcome, _ := tracker.apply(event, translationTime, nil); outcome != "queued" {
			t.Fatalf("rule %d failed before capacity: %s", rule, outcome)
		}
	}
	newRule := normalizedTranslationEvent(t, "CrossLineDetection", "Start", 0, map[string]any{"RuleID": maxTrackedAlarmKeys})
	if wires, outcome, _ := tracker.apply(newRule, translationTime, nil); outcome != "tracking_full" || len(wires) != 0 || len(tracker) != maxTrackedAlarmKeys {
		t.Fatalf("capacity failure mutated or emitted an alarm: outcome=%s keys=%d", outcome, len(tracker))
	}
	existing := normalizedTranslationEvent(t, "CrossLineDetection", "Start", 0, map[string]any{"RuleID": 0})
	if _, outcome, _ := tracker.apply(existing, translationTime.Add(time.Second), nil); outcome != "queued" {
		t.Fatalf("capacity blocked an existing alarm refresh: %s", outcome)
	}
	candidate := tracker.clone()
	existing.Action = "Stop"
	candidate.apply(existing, translationTime.Add(2*time.Second), nil)
	if len(candidate) != maxTrackedAlarmKeys-1 || len(tracker) != maxTrackedAlarmKeys || len(tracker[alarmKey(existing)]) != 1 {
		t.Fatal("candidate mutation changed the original tracker")
	}
	if _, outcome, _ := candidate.apply(newRule, translationTime.Add(3*time.Second), nil); outcome != "queued" || len(candidate) != maxTrackedAlarmKeys {
		t.Fatal("released tracker capacity was not reusable")
	}
}

func TestTranslationDoesNotUsePhysicalRuleAsOmadaRegion(t *testing.T) {
	event := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0, map[string]any{"RuleID": 77, "RegionID": 91, "ObjectType": "Human"})
	wires, ok := nativeEvents(event)
	if !ok {
		t.Fatal("classified intrusion did not translate")
	}
	assertTranslatedEvents(t, wires, 1, omadalink.EventHumanIntrusion)
	encoded, err := json.Marshal(wires[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != fmt.Sprintf(`{"event_type":%d,"event_status":1}`, omadalink.EventHumanIntrusion) {
		t.Fatalf("wire payload invented source region metadata: %s", encoded)
	}
}

func TestTranslationCanonicalRuleAndDiscriminatorValuesShareAlarmKey(t *testing.T) {
	canonical := cameraevents.Event{
		Code: "CrossRegionDetection", SourceIndex: 1, Discriminator: "336700",
		RuleIDs: map[string]any{"RuleID": "7", "WindowId": []any{"2", map[string]any{"nested": "3"}}},
	}
	for _, representation := range []struct {
		name                          string
		rule, window, nested, subtype any
	}{
		{"native integers", 7, 2, 3, 336700},
		{"int64", int64(7), int64(2), int64(3), int64(336700)},
		{"decoded JSON numbers", json.Number("7"), json.Number("2"), json.Number("3"), json.Number("336700")},
		{"floating JSON decoder", float64(7), float64(2), float64(3), float64(336700)},
		{"decimal strings", "7", "2", "3", "336700"},
	} {
		t.Run(representation.name, func(t *testing.T) {
			event := canonical
			event.Discriminator = representation.subtype
			event.RuleIDs = map[string]any{"RuleID": representation.rule, "WindowId": []any{representation.window, map[string]any{"nested": representation.nested}}}
			if alarmKey(event) != alarmKey(canonical) {
				t.Fatal("equivalent numeric and string provenance produced different alarm keys")
			}
			if !reflect.DeepEqual(event.RuleIDs["RuleID"], representation.rule) || !reflect.DeepEqual(event.Discriminator, representation.subtype) {
				t.Fatal("identity normalization changed the source event provenance")
			}
		})
	}

	other := canonical
	other.RuleIDs = map[string]any{"RuleID": "8", "WindowId": canonical.RuleIDs["WindowId"]}
	if alarmKey(other) == alarmKey(canonical) {
		t.Fatal("distinct rule numbers collapsed into one key")
	}
	other = canonical
	other.Discriminator = "336701"
	if alarmKey(other) == alarmKey(canonical) {
		t.Fatal("distinct discriminators collapsed into one key")
	}
}

func TestTranslationSparseStopMatchesSubsetAndNumericRuleIDs(t *testing.T) {
	tracker := make(alarmTracker)
	start := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0, map[string]any{
		"RuleID": 7, "WindowId": []any{2, 3}, "event": json.Number("336700"), "ObjectType": "Human",
	})
	tracker.apply(start, translationTime, nil)
	stop := normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 0, map[string]any{
		"RuleID": "7", "event": "336700",
	})
	matched, ambiguous := tracker.matchingStopKey(stop)
	if ambiguous || matched != alarmKey(start) {
		t.Fatalf("sparse numeric/string rule match: key=%q ambiguous=%t", matched, ambiguous)
	}
	wires, outcome, _ := tracker.apply(stop, translationTime.Add(time.Second), nil)
	if outcome != "queued" || len(tracker) != 0 {
		t.Fatalf("sparse classified Stop outcome=%s remaining=%d", outcome, len(tracker))
	}
	assertTranslatedEvents(t, wires, 3, omadalink.EventHumanIntrusion)
}

func TestTranslationStopWithoutRulesClosesSingleCompatibleInterval(t *testing.T) {
	tracker := make(alarmTracker)
	start := normalizedTranslationEvent(t, "CrossLineDetection", "Start", 0, map[string]any{
		"RuleID": 7, "WindowId": []any{1}, "event": "line-source", "ObjectTypes": []any{"Human", "Vehicle"},
	})
	tracker.apply(start, translationTime, nil)
	stop := normalizedTranslationEvent(t, "CrossLineDetection", "Stop", 0, nil)
	wires, outcome, _ := tracker.apply(stop, translationTime.Add(time.Second), nil)
	if outcome != "queued" || len(tracker) != 0 {
		t.Fatalf("single sparse Stop outcome=%s remaining=%d", outcome, len(tracker))
	}
	assertTranslatedEvents(t, wires, 3, omadalink.EventHumanLine, omadalink.EventVehicleLine)
}

func TestTranslationStopWithoutRulesDoesNotGuessBetweenIntervals(t *testing.T) {
	tracker := make(alarmTracker)
	for rule, class := range map[int]string{7: "Human", 8: "Vehicle"} {
		start := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0, map[string]any{"RuleID": rule, "ObjectType": class})
		tracker.apply(start, translationTime, nil)
	}
	before := tracker.clone()
	stop := normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 0, nil)
	matched, ambiguous := tracker.matchingStopKey(stop)
	if matched != "" || !ambiguous {
		t.Fatalf("ambiguous source Stop selected a rule: key=%q ambiguous=%t", matched, ambiguous)
	}
	wires, outcome, suppressed := tracker.apply(stop, translationTime.Add(time.Second), nil)
	if outcome != "ambiguous_stop" || len(wires) != 0 || suppressed != 0 || !reflect.DeepEqual(tracker, before) {
		t.Fatalf("ambiguous Stop mutated active alarms: outcome=%s wires=%#v remaining=%d", outcome, wires, len(tracker))
	}
}

func TestTranslationSparseStopCannotCrossEventSourceOrDiscriminator(t *testing.T) {
	tracker := make(alarmTracker)
	start := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 1, map[string]any{"RuleID": 7, "event": "336700", "ObjectType": "Human"})
	tracker.apply(start, translationTime, nil)
	for _, stop := range []cameraevents.Event{
		normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 0, nil),
		normalizedTranslationEvent(t, "CrossLineDetection", "Stop", 1, nil),
		normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 1, map[string]any{"event": "336701"}),
		normalizedTranslationEvent(t, "CrossRegionDetection", "Stop", 1, map[string]any{"RuleID": 8}),
	} {
		if matched, ambiguous := tracker.matchingStopKey(stop); matched != "" || ambiguous {
			t.Fatalf("unrelated Stop matched active interval: key=%q ambiguous=%t", matched, ambiguous)
		}
	}
}

func TestTranslationClassifiedStopClosesMatchingGenericIVSStart(t *testing.T) {
	for _, test := range []struct {
		code                    string
		generic, human, vehicle omadalink.EventType
	}{
		{"CrossLineDetection", omadalink.EventLineCrossing, omadalink.EventHumanLine, omadalink.EventVehicleLine},
		{"CrossRegionDetection", omadalink.EventIntrusion, omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion},
	} {
		t.Run(test.code, func(t *testing.T) {
			tracker := make(alarmTracker)
			genericStart := normalizedTranslationEvent(t, test.code, "Start", 0, map[string]any{"RuleID": 7})
			tracker.apply(genericStart, translationTime, nil)
			classifiedStop := normalizedTranslationEvent(t, test.code, "Stop", 0, map[string]any{"RuleID": "7", "ObjectType": "Human"})
			wires, outcome, _ := tracker.apply(classifiedStop, translationTime.Add(time.Second), nil)
			if outcome != "queued" || len(tracker) != 0 {
				t.Fatalf("classified Stop left generic interval active: outcome=%s remaining=%d", outcome, len(tracker))
			}
			assertTranslatedEvents(t, wires, 3, test.human, test.generic)

			// A stop for another classification must still close the generic
			// fallback, but not a genuine human interval on the same source rule.
			tracker.apply(genericStart, translationTime, nil)
			humanStart := normalizedTranslationEvent(t, test.code, "Start", 0, map[string]any{"RuleID": 7, "ObjectType": "Human"})
			tracker.apply(humanStart, translationTime, nil)
			vehicleStop := normalizedTranslationEvent(t, test.code, "Stop", 0, map[string]any{"RuleID": 7, "ObjectType": "Vehicle"})
			wires, outcome, _ = tracker.apply(vehicleStop, translationTime.Add(time.Second), nil)
			assertTranslatedEvents(t, wires, 3, test.vehicle, test.generic)
			if outcome != "queued" || tracker.has(test.generic) || !tracker.has(test.human) || len(tracker[alarmKey(humanStart)]) != 1 {
				t.Fatal("classified Stop closed a different class or retained generic fallback")
			}
			humanStart.Action = "Stop"
			wires, _, _ = tracker.apply(humanStart, translationTime.Add(2*time.Second), nil)
			assertTranslatedEvents(t, wires, 3, test.human)
			if len(tracker) != 0 {
				t.Fatal("matching human Stop did not close the remaining interval")
			}

			// Generic and sparse stops already include the generic wire type.
			tracker.apply(genericStart, translationTime, nil)
			genericStart.Action = "Stop"
			wires, _, _ = tracker.apply(genericStart, translationTime.Add(time.Second), nil)
			assertTranslatedEvents(t, wires, 3, test.generic)
		})
	}
}
