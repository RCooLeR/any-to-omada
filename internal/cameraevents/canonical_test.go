package cameraevents

import (
	"reflect"
	"testing"
	"time"
)

func TestCanonicalEventsNormalizeLikeNativeOnes(t *testing.T) {
	received := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		payload            map[string]any
		kind, class, index string
		classes            []string
	}{
		{Canonical(CodeMotion, "Start", 0, "onvif:RuleEngine/CellMotionDetector/Motion", nil, "MyRule"), "motion", "unknown", "0", nil},
		{Canonical(CodePetMotion, "Start", 1, "onvif:RuleEngine/MyRuleDetector/DogCatDetect", nil, ""), "smart_motion", "pet", "1", nil},
		{Canonical(CodeIntrusion, "Start", 0, "isapi:fielddetection", []string{"human", "vehicle"}, "2"), "intrusion", "unknown", "0", []string{"human", "vehicle"}},
		{Canonical(CodeLineCrossing, "Pulse", -1, "isapi:linedetection", []string{"human"}, ""), "line_crossing", "human", "-1", []string{"human"}},
	} {
		events, err := Normalize("cam", received, tc.payload, nil)
		if err != nil || len(events) != 1 {
			t.Fatalf("%v: %v %v", tc.payload, events, err)
		}
		event := events[0]
		if event.Kind != tc.kind || event.Class != tc.class || formatIndex(event.SourceIndex) != tc.index || !reflect.DeepEqual(event.Classes, tc.classes) {
			t.Fatalf("%v normalized to %+v", tc.payload, event)
		}
		if event.Discriminator != tc.payload["Data"].(map[string]any)["event"] {
			t.Fatal("provenance lost")
		}
	}
}

func formatIndex(index int) string {
	switch index {
	case -1:
		return "-1"
	case 0:
		return "0"
	case 1:
		return "1"
	}
	return "other"
}
