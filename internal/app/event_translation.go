package app

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

// A source Pulse has no stop edge. Represent it as a bounded virtual interval,
// not wire status 2, which has a different meaning in the Omada protocol.
const translatedPulseDuration = time.Second
const maxTrackedAlarmKeys = 128

// alarmHold retains a detection start and optional synthetic expiry; a zero expiry waits for
// a source Stop edge.
type alarmHold struct {
	started time.Time
	expires time.Time // Zero denotes a source-controlled Start/Stop interval.
}

// alarmTracker belongs to one virtual camera and callback generation. Rule and
// source provenance separates overlapping alarms; no source rule number is
// invented as an Omada region number.
type alarmTracker map[string]map[omadalink.EventType]alarmHold

// clone copies nested alarm state so translation can be rolled back when the callback queue
// lacks capacity.
func (a alarmTracker) clone() alarmTracker {
	copy := make(alarmTracker, len(a))
	for key, types := range a {
		copy[key] = make(map[omadalink.EventType]alarmHold, len(types))
		for eventType, hold := range types {
			copy[key][eventType] = hold
		}
	}
	return copy
}

// alarmKey combines native code, source index, and canonicalized rule/discriminator
// provenance to keep overlapping alarms separate.
func alarmKey(event cameraevents.Event) string {
	provenance, _ := json.Marshal(struct {
		Rules         map[string]any
		Discriminator any
	}{canonicalAlarmValue(event.RuleIDs).(map[string]any), canonicalAlarmValue(event.Discriminator)})
	return event.Code + "\x00" + strconv.Itoa(event.SourceIndex) + "\x00" + string(provenance)
}

// canonicalAlarmValue unifies numeric and decimal-string rule/discriminator
// identities across DVRIP and CGI. Journaled native values remain unchanged.
func canonicalAlarmValue(value any) any {
	switch value := value.(type) {
	case json.Number:
		return value.String()
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case map[string]any:
		copy := make(map[string]any, len(value))
		for key, child := range value {
			copy[key] = canonicalAlarmValue(child)
		}
		return copy
	case []any:
		copy := make([]any, len(value))
		for index, child := range value {
			copy[index] = canonicalAlarmValue(child)
		}
		return copy
	default:
		return value
	}
}

// matchingStopKey allows a sparse stop to close one compatible interval, never
// guessing between rules.
// Extra start-only provenance is permitted; every field present on the stop
// must match. An empty result leaves the caller's ordinary stop handling intact.
func (a alarmTracker) matchingStopKey(event cameraevents.Event) (string, bool) {
	prefix := event.Code + "\x00" + strconv.Itoa(event.SourceIndex) + "\x00"
	stop := canonicalAlarmValue(event.RuleIDs).(map[string]any)
	discriminator, _ := json.Marshal(canonicalAlarmValue(event.Discriminator))
	match := ""
	for key := range a {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		var start struct {
			Rules         map[string]json.RawMessage
			Discriminator json.RawMessage
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(key, prefix)), &start) != nil {
			continue
		}
		if event.Discriminator != nil && string(start.Discriminator) != string(discriminator) {
			continue
		}
		compatible := true
		for field, value := range stop {
			encoded, _ := json.Marshal(value)
			if string(start.Rules[field]) != string(encoded) {
				compatible = false
				break
			}
		}
		if compatible {
			if match != "" {
				return "", true
			}
			match = key
		}
	}
	return match, false
}

// has reports whether any source interval still holds a particular Omada event type active.
func (a alarmTracker) has(eventType omadalink.EventType) bool {
	for _, types := range a {
		if _, ok := types[eventType]; ok {
			return true
		}
	}
	return false
}

// sortedTypes orders event IDs numerically so generated stop notifications have a
// deterministic sequence.
func sortedTypes(types map[omadalink.EventType]alarmHold) []omadalink.EventType {
	result := make([]omadalink.EventType, 0, len(types))
	for eventType := range types {
		result = append(result, eventType)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// apply mutates a candidate snapshot. The caller commits it only when every
// resulting wire notification fits the bounded callback queue.
func (a alarmTracker) apply(event cameraevents.Event, now time.Time, allow func(omadalink.EventType) bool) ([]omadalink.Event, string, uint64) {
	wires, ok := nativeEvents(event)
	key := alarmKey(event)
	previous := a[key]
	if event.Action == "Stop" && len(previous) == 0 {
		matched, ambiguous := a.matchingStopKey(event)
		if ambiguous {
			return nil, "ambiguous_stop", 0
		}
		if matched != "" {
			key, previous = matched, a[matched]
		}
	}
	if event.Action == "Stop" && len(previous) > 0 && (event.Class == "unknown" || event.Class == "") && len(event.Classes) == 0 {
		// IVS stop notifications can omit the object carried by the start.
		wires = nil
		for _, eventType := range sortedTypes(previous) {
			wires = append(wires, omadalink.Event{Type: eventType, Status: 3})
		}
		ok = true
	}
	if !ok {
		return nil, "unmapped", 0
	}
	if event.Action == "Stop" {
		// Some IVS notifications gain classification only on the stop edge.
		// Close the same rule's generic start too, without stopping any other
		// explicitly classified intervals still held for this rule.
		generic := omadalink.EventType(0)
		switch event.Code {
		case "CrossLineDetection":
			generic = omadalink.EventLineCrossing
		case "CrossRegionDetection":
			generic = omadalink.EventIntrusion
		}
		if _, held := previous[generic]; held {
			included := false
			for _, wire := range wires {
				if wire.Type == generic {
					included = true
					break
				}
			}
			if !included {
				wires = append(wires, omadalink.Event{Type: generic, Status: 3})
			}
		}
		result := []omadalink.Event{}
		for _, wire := range wires {
			delete(previous, wire.Type)
			if !a.has(wire.Type) {
				result = append(result, wire)
			}
		}
		if len(previous) == 0 {
			delete(a, key)
		}
		return result, "queued", 0
	}
	accepted := []omadalink.Event{}
	var suppressed uint64
	for _, wire := range wires {
		if allow != nil && !allow(wire.Type) {
			suppressed++
			continue
		}
		accepted = append(accepted, wire)
	}
	if len(accepted) == 0 {
		return nil, "disabled_by_settings", suppressed
	}
	if previous == nil {
		if len(a) >= maxTrackedAlarmKeys {
			return nil, "tracking_full", suppressed
		}
		previous = make(map[omadalink.EventType]alarmHold)
		a[key] = previous
	}
	for _, wire := range accepted {
		hold, exists := previous[wire.Type]
		if event.Action == "Start" {
			hold = alarmHold{started: now}
		} else if !exists || !hold.expires.IsZero() {
			// A pulse must not shorten an existing source-controlled interval.
			hold = alarmHold{started: now, expires: now.Add(translatedPulseDuration)}
		}
		previous[wire.Type] = hold
	}
	return accepted, "queued", suppressed
}

// expire removes elapsed synthetic intervals and emits a stop only after the final
// overlapping holder of that event type closes.
func (a alarmTracker) expire(now time.Time) []omadalink.Event {
	removed := make(map[omadalink.EventType]alarmHold)
	for key, types := range a {
		for eventType, hold := range types {
			if !hold.expires.IsZero() && !now.Before(hold.expires) {
				delete(types, eventType)
				removed[eventType] = hold
			}
		}
		if len(types) == 0 {
			delete(a, key)
		}
	}
	result := []omadalink.Event{}
	for _, eventType := range sortedTypes(removed) {
		if !a.has(eventType) {
			result = append(result, omadalink.Event{Type: eventType, Status: 3})
		}
	}
	return result
}

// intrusionStart returns the newest open intrusion start in Unix nanoseconds, or zero when
// no intrusion remains.
func (a alarmTracker) intrusionStart() int64 {
	var latest time.Time
	for _, types := range a {
		for eventType, hold := range types {
			switch eventType {
			case omadalink.EventIntrusion, omadalink.EventHumanIntrusion, omadalink.EventVehicleIntrusion, omadalink.EventPetIntrusion:
				if hold.started.After(latest) {
					latest = hold.started
				}
			}
		}
	}
	if latest.IsZero() {
		return 0
	}
	return latest.UnixNano()
}

// nativeEvents maps explicit source semantics to the observed Omada event
// table. Pulse returns the initial edge; alarmTracker produces its later stop.
func nativeEvents(event cameraevents.Event) ([]omadalink.Event, bool) {
	status := uint8(1)
	switch event.Action {
	case "Start", "Pulse":
	case "Stop":
		status = 3
	default:
		return nil, false
	}
	var types []omadalink.EventType
	switch event.Code {
	case "VideoMotion":
		types = []omadalink.EventType{omadalink.EventMotion}
	case "SmartMotionHuman":
		types = []omadalink.EventType{omadalink.EventHumanMotion}
	case "SmartMotionVehicle":
		types = []omadalink.EventType{omadalink.EventVehicleMotion}
	case cameraevents.CodePetMotion:
		types = []omadalink.EventType{omadalink.EventPetMotion}
	case "VideoBlind":
		types = []omadalink.EventType{omadalink.EventTamper}
	case "CrossLineDetection", "CrossRegionDetection":
		line := event.Code == "CrossLineDetection"
		classes := event.Classes
		if event.Evidence != "native_object" {
			classes = nil
		} else if len(classes) == 0 {
			classes = []string{event.Class}
		}
		for _, class := range classes {
			var eventType omadalink.EventType
			switch class {
			case "human":
				eventType = omadalink.EventHumanIntrusion
				if line {
					eventType = omadalink.EventHumanLine
				}
			case "vehicle":
				eventType = omadalink.EventVehicleIntrusion
				if line {
					eventType = omadalink.EventVehicleLine
				}
			case "pet":
				eventType = omadalink.EventPetIntrusion
				if line {
					eventType = omadalink.EventPetLine
				}
			default:
				continue
			}
			types = append(types, eventType)
		}
		if len(types) == 0 {
			types = []omadalink.EventType{omadalink.EventIntrusion}
			if line {
				types[0] = omadalink.EventLineCrossing
			}
		}
	case "Intelligent":
		// Preserve the operator-correlated virtual whole-frame intrusion mapping
		// that was verified in recorder history; no fleet-wide numeric guess.
		if event.Evidence != "operator_correlated" {
			return nil, false
		}
		switch event.Class {
		case "human":
			types = []omadalink.EventType{omadalink.EventHumanIntrusion}
		case "vehicle":
			types = []omadalink.EventType{omadalink.EventVehicleIntrusion}
		case "pet":
			types = []omadalink.EventType{omadalink.EventPetIntrusion}
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	result := make([]omadalink.Event, 0, len(types))
	seen := map[omadalink.EventType]bool{}
	for _, eventType := range types {
		if !seen[eventType] {
			result = append(result, omadalink.Event{Type: eventType, Status: status})
			seen[eventType] = true
		}
	}
	return result, len(result) > 0
}
