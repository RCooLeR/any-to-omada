package isapievents

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
)

// detection is one brand-neutral meaning of an alert.
type detection struct {
	code    string
	classes []string
}

// detections maps documented ISAPI event types. A motion alert that carries a
// target class (AcuSense) is both motion and the class's smart motion.
// Unknown types are journaled only.
func detections(a alert) []detection {
	classes := targetClasses(a.TargetTypes)
	switch strings.ToLower(a.EventType) {
	case "vmd", "vmdhumanvehicle", "pir":
		result := []detection{{code: cameraevents.CodeMotion}}
		for _, class := range classes {
			switch class {
			case "human":
				result = append(result, detection{code: cameraevents.CodeHumanMotion})
			case "vehicle":
				result = append(result, detection{code: cameraevents.CodeVehicleMotion})
			case "pet":
				result = append(result, detection{code: cameraevents.CodePetMotion})
			}
		}
		return result
	case "linedetection":
		return []detection{{code: cameraevents.CodeLineCrossing, classes: classes}}
	case "fielddetection", "regionentrance", "regionexiting", "regionexit":
		return []detection{{code: cameraevents.CodeIntrusion, classes: classes}}
	case "shelteralarm", "tamperdetection":
		return []detection{{code: cameraevents.CodeTamper}}
	}
	return nil
}

// targetClasses maps explicit target labels to a sorted, unique set of human, vehicle, and pet classes.
func targetClasses(labels []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, label := range labels {
		class := ""
		switch strings.ToLower(label) {
		case "human", "people", "person":
			class = "human"
		case "vehicle", "car", "motorvehicle", "nonmotorvehicle":
			class = "vehicle"
		case "animal", "pet":
			class = "pet"
		}
		if class != "" && !seen[class] {
			seen[class] = true
			result = append(result, class)
		}
	}
	sort.Strings(result)
	return result
}

// lens converts the 1-based ISAPI channel to the translator's 0-based index.
// NVRs can report IP channels in dynChannelID. No model-specific channel
// offset is assumed; an unavailable or malformed channel remains unknown.
func (a alert) lens() int {
	value := a.ChannelID
	if a.DynChannelID != "" {
		value = a.DynChannelID
	}
	if channel, err := strconv.Atoi(value); err == nil && channel >= 1 && channel <= 65536 {
		return channel - 1
	}
	return -1
}

// interval retains the source, rule, and class context needed to emit a matching Stop after quiet expiry.
type interval struct {
	code, provenance, rule string
	index                  int
	classes                []string
	last                   time.Time
}

// tracker folds repeated "active" alerts into intervals.
type tracker struct {
	quiet time.Duration
	open  map[string]*interval
}

// newTracker creates an empty interval set whose detections expire after the supplied quiet duration.
func newTracker(quiet time.Duration) *tracker {
	return &tracker{quiet: quiet, open: map[string]*interval{}}
}

// apply folds active repeats into at most 128 open intervals and emits transitions only for
// recognized active/inactive states.
func (t *tracker) apply(a alert, now time.Time) []map[string]any {
	state := strings.ToLower(a.EventState)
	if state != "active" && state != "inactive" {
		return nil
	}
	rule := ""
	if len(a.RegionIDs) > 0 {
		rule = a.RegionIDs[0]
	}
	if state == "inactive" {
		return t.stop(a, rule)
	}
	var result []map[string]any
	for _, found := range detections(a) {
		key := found.code + "\x00" + strconv.Itoa(a.lens()) + "\x00" + strings.ToLower(a.EventType) + "\x00" + rule + "\x00" + strings.Join(found.classes, ",")
		open := t.open[key]
		if open != nil {
			open.last = now
			continue
		}
		if len(t.open) >= 128 {
			continue
		}
		open = &interval{code: found.code, provenance: protocol + ":" + a.EventType, rule: rule, index: a.lens(), classes: found.classes, last: now}
		t.open[key] = open
		result = append(result, open.event("Start"))
	}
	return result
}

// stop uses the active interval's class and rule when a camera omits those
// fields on its inactive notification. Multiple possible rules/classes are
// left open for quiet expiry rather than closing an unrelated detection.
func (t *tracker) stop(a alert, rule string) []map[string]any {
	classes := targetClasses(a.TargetTypes)
	if len(a.TargetTypes) > 0 && len(classes) == 0 {
		return nil
	}
	var keys []string
	groups := map[string]bool{}
	for key, open := range t.open {
		if open.index != a.lens() || !strings.EqualFold(open.provenance, protocol+":"+a.EventType) || (rule != "" && open.rule != rule) {
			continue
		}
		foundClasses := open.classes
		switch open.code {
		case cameraevents.CodeHumanMotion:
			foundClasses = []string{"human"}
		case cameraevents.CodeVehicleMotion:
			foundClasses = []string{"vehicle"}
		case cameraevents.CodePetMotion:
			foundClasses = []string{"pet"}
		}
		if len(classes) > 0 && len(foundClasses) > 0 {
			if len(foundClasses) == 1 {
				if !slices.Contains(classes, foundClasses[0]) {
					continue
				}
			} else if strings.Join(classes, ",") != strings.Join(foundClasses, ",") {
				continue
			}
		}
		keys = append(keys, key)
		if open.code != cameraevents.CodeMotion {
			groups[open.rule+"\x00"+strings.Join(foundClasses, ",")] = true
		}
	}
	// Generic motion can accompany a classified event. It does not make that
	// same rule ambiguous, but distinct rules still do.
	rules := map[string]bool{}
	for _, key := range keys {
		rules[t.open[key].rule] = true
	}
	if len(rules) > 1 || (len(classes) == 0 && len(groups) > 1) {
		return nil
	}
	sort.Strings(keys)
	var result []map[string]any
	for _, key := range keys {
		open := t.open[key]
		if open.code == cameraevents.CodeMotion {
			remaining := false
			for otherKey, other := range t.open {
				if other.index == open.index && other.rule == open.rule && other.provenance == open.provenance && !slices.Contains(keys, otherKey) {
					remaining = true
					break
				}
			}
			if remaining {
				continue
			}
		}
		result = append(result, open.event("Stop"))
		delete(t.open, key)
	}
	return result
}

// expire ends intervals whose alerts stopped repeating.
func (t *tracker) expire(now time.Time) []map[string]any {
	var keys []string
	for key, open := range t.open {
		if now.Sub(open.last) >= t.quiet {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		result = append(result, t.open[key].event("Stop"))
		delete(t.open, key)
	}
	return result
}

// event builds a canonical edge from the interval context so its start and stop retain identical provenance.
func (i *interval) event(action string) map[string]any {
	return cameraevents.Canonical(i.code, action, i.index, i.provenance, i.classes, i.rule)
}
