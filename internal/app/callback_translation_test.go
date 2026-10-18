package app

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func translationCallback(t *testing.T, capacity int) *callback {
	t.Helper()
	c := newCallback(t.Context(), "fixture", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.active = &callbackAttempt{events: make(chan omadalink.Event, capacity), cancel: func() {}}
	c.status.State = "connected"
	t.Cleanup(c.close)
	return c
}

func TestCallbackTranslationFanoutIsAtomicAndSettingsFilterClasses(t *testing.T) {
	c := translationCallback(t, 2)
	event := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0,
		map[string]any{"ObjectTypes": []any{"Human", "Vehicle", "Pet"}})
	if c.send(event) != "queue_full" || len(c.active.events) != 0 || len(c.alarms) != 0 || c.markerState().IntrusionActive {
		t.Fatal("partial mixed-class admission changed queue or marker state")
	}
	c.allow = func(eventType omadalink.EventType) bool { return eventType != omadalink.EventPetIntrusion }
	if c.send(event) != "queued" || !c.markerState().IntrusionActive {
		t.Fatal("enabled classes did not fit after filtering")
	}
	assertTranslatedEvents(t, []omadalink.Event{<-c.active.events, <-c.active.events}, 1,
		omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion)
	if c.snapshot().EventsSuppressed != 1 || c.snapshot().EventsDropped != 1 {
		t.Fatal("translation outcomes were not counted")
	}
}

func TestCallbackTranslationPulseStopRetriesFullQueue(t *testing.T) {
	c := translationCallback(t, 1)
	event := normalizedTranslationEvent(t, "CrossRegionDetection", "Pulse", 0,
		map[string]any{"ObjectType": "Human"})
	if c.send(event) != "queued" {
		t.Fatal("pulse not accepted")
	}
	after := time.Now().Add(2 * translatedPulseDuration)
	c.expireAlarms(c.active, after)
	if len(c.alarms) != 1 || !c.markerState().IntrusionActive {
		t.Fatal("full queue lost pending stop")
	}
	assertTranslatedEvents(t, []omadalink.Event{<-c.active.events}, 1, omadalink.EventHumanIntrusion)
	c.expireAlarms(c.active, after)
	assertTranslatedEvents(t, []omadalink.Event{<-c.active.events}, 3, omadalink.EventHumanIntrusion)
	if len(c.alarms) != 0 || c.markerState().IntrusionActive {
		t.Fatal("pulse stop did not close marker and tracker")
	}
}

func TestCallbackTranslationSourceDisconnectClosesIntervalsAndOldAttemptCannotExpire(t *testing.T) {
	c := translationCallback(t, 4)
	event := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0,
		map[string]any{"ObjectType": "Human"})
	c.send(event)
	<-c.active.events
	c.sourceDisconnected()
	c.expireAlarms(&callbackAttempt{}, time.Now().Add(time.Second))
	if len(c.active.events) != 0 || len(c.alarms) != 1 {
		t.Fatal("foreign generation changed alarm state")
	}
	c.expireAlarms(c.active, time.Now().Add(time.Second))
	assertTranslatedEvents(t, []omadalink.Event{<-c.active.events}, 3, omadalink.EventHumanIntrusion)
	if len(c.alarms) != 0 || c.markerState().IntrusionActive {
		t.Fatal("source outage left active alarms")
	}
	c.send(event)
	old := c.active
	c.mu.Lock()
	c.releaseAccountState()
	c.active = &callbackAttempt{events: make(chan omadalink.Event, 4), cancel: func() {}}
	c.mu.Unlock()
	c.expireAlarms(old, time.Now().Add(time.Hour))
	if len(c.alarms) != 0 || c.markerState().IntrusionActive || len(c.active.events) != 0 {
		t.Fatal("callback replacement retained alarm state")
	}
}

func TestCallbackTranslationOverlappingIntrusionsKeepMarkerUntilFinalStop(t *testing.T) {
	c := translationCallback(t, 8)
	first := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0,
		map[string]any{"RuleID": 1, "ObjectType": "Human"})
	second := normalizedTranslationEvent(t, "CrossRegionDetection", "Start", 0,
		map[string]any{"RuleID": 2, "ObjectType": "Human"})
	c.send(first)
	c.send(second)
	<-c.active.events
	<-c.active.events
	first.Action = "Stop"
	if c.send(first) != "queued" || len(c.active.events) != 0 || !c.markerState().IntrusionActive {
		t.Fatal("first rule stopped the other rule's shared alarm")
	}
	second.Action = "Stop"
	if c.send(second) != "queued" || c.markerState().IntrusionActive {
		t.Fatal("last rule failed to clear shared alarm")
	}
	assertTranslatedEvents(t, []omadalink.Event{<-c.active.events}, 3, omadalink.EventHumanIntrusion)
}

func TestCallbackTranslationUnknownEventsRemainObservableWithoutAlarm(t *testing.T) {
	c := translationCallback(t, 8)
	for _, code := range []string{"Intelligent", "RtspSessionDisconnect", "InterVideoAccess", "VideoMotionInfo"} {
		if c.send(cameraevents.Event{Code: code, Action: "Start", Class: "unknown"}) != "unmapped" {
			t.Fatalf("unknown notification %s was promoted to an alarm", code)
		}
	}
	if c.snapshot().EventsUnmapped != 4 || len(c.active.events) != 0 || len(c.alarms) != 0 {
		t.Fatal("unmapped notification accounting is incorrect")
	}
}
