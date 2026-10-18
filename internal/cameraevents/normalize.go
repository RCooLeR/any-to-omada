// Package cameraevents normalizes captured camera notifications without changing
// device state, inventing classifications, or merging events across sources.
package cameraevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	maxPayloadBytes = 2 << 20
	maxNodes        = 20000
	maxDepth        = 16
	maxEvents       = 256
	maxFieldBytes   = 256
)

// Mapping is an explicitly enabled classification for one device, source and
// native discriminator. An empty device or negative source is never a wildcard.
type Mapping struct {
	DeviceID      string `json:"device_id"`
	SourceIndex   int    `json:"source_index"`
	Code          string `json:"code"`
	Discriminator string `json:"discriminator"`
	Class         string `json:"class"`
}

// Event preserves source and timestamp provenance. SourceIndex is -1 when absent;
// zero is a real first source. DeviceUTC and DeviceRealUTC retain the camera's
// numeric values without applying clock corrections. Class defaults to unknown.
// Classes contains explicit IVS object classes in human/vehicle/pet order; Class
// is set only when Classes has one entry. ObjectTypes preserves the source labels.
type Event struct {
	DeviceID      string         `json:"device_id"`
	SourceIndex   int            `json:"source_index"`
	Code          string         `json:"code"`
	Action        string         `json:"action"`
	ReceivedUTC   time.Time      `json:"received_utc"`
	DeviceUTC     json.Number    `json:"device_utc,omitempty"`
	DeviceRealUTC json.Number    `json:"device_real_utc,omitempty"`
	LocaleTime    string         `json:"locale_time,omitempty"`
	Discriminator any            `json:"discriminator,omitempty"`
	Kind          string         `json:"kind"`
	Class         string         `json:"class"`
	Classes       []string       `json:"classes,omitempty"`
	Evidence      string         `json:"evidence"`
	ObjectTypes   []string       `json:"object_types,omitempty"`
	RuleIDs       map[string]any `json:"rule_ids,omitempty"`
}

// Normalize accepts a decoded JSON object, JSON bytes, json.RawMessage, or JSON
// text. Whole collector records must have kind=event and match deviceID. Direct
// payloads must be client.notifyEventStream or a CGI Code/Action event. Responses
// and other collector kinds return no events. Malformed, oversized or ambiguous
// inputs fail atomically. The function has no I/O, logging, or lifecycle state.
func Normalize(deviceID string, received time.Time, payload any, mappings []Mapping) ([]Event, error) {
	if !validText(deviceID, maxFieldBytes) || deviceID == "" || received.IsZero() {
		return nil, errors.New("event context is invalid")
	}
	if err := validateMappings(mappings); err != nil {
		return nil, err
	}
	object, err := decodeObject(payload)
	if err != nil {
		return nil, err
	}
	if kind, present := object["kind"]; present {
		if kind != "event" {
			return nil, nil
		}
		if id, present := object["device_id"]; present && id != deviceID {
			return nil, errors.New("event device does not match context")
		}
		object, _ = object["data"].(map[string]any)
		if object == nil {
			return nil, errors.New("event payload is not an object")
		}
	}
	var entries []any
	if method, present := object["method"]; present {
		if method != "client.notifyEventStream" {
			return nil, nil
		}
		params, _ := object["params"].(map[string]any)
		entries, _ = params["eventList"].([]any)
		if entries == nil {
			return nil, errors.New("event notification list is invalid")
		}
	} else if _, present := object["Code"]; present {
		// CGI notifications have no method. RPC response wrappers are never events.
		if _, response := object["response"]; response {
			return nil, nil
		}
		if _, response := object["result"]; response {
			return nil, nil
		}
		entries = []any{object}
	} else {
		return nil, nil
	}
	if len(entries) > maxEvents {
		return nil, errors.New("event notification list exceeds limit")
	}
	events := make([]Event, 0, len(entries))
	for _, entry := range entries {
		event, err := normalizeEntry(deviceID, received, entry, mappings)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// normalizeEntry validates one native event and records only classifications supported by
// its code, object labels, or an exact operator mapping.
func normalizeEntry(deviceID string, received time.Time, value any, mappings []Mapping) (Event, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return Event{}, errors.New("event entry is not an object")
	}
	code, ok := object["Code"].(string)
	if !ok || code == "" || !validText(code, maxFieldBytes) {
		return Event{}, errors.New("event code is invalid")
	}
	action, ok := first(object, "Action", "action").(string)
	if !ok || action == "" || !validText(action, maxFieldBytes) {
		return Event{}, errors.New("event action is invalid")
	}
	index := -1
	if raw := first(object, "Index", "index"); raw != nil {
		number, ok := numberText(raw)
		parsed, err := strconv.ParseInt(number.String(), 10, 32)
		if !ok || err != nil || parsed < 0 || parsed > 65535 {
			return Event{}, errors.New("event source index is invalid")
		}
		index = int(parsed)
	}
	data := map[string]any{}
	if raw := first(object, "Data", "data"); raw != nil {
		var ok bool
		data, ok = raw.(map[string]any)
		if !ok {
			return Event{}, errors.New("event data is invalid")
		}
	}
	event := Event{DeviceID: deviceID, SourceIndex: index, Code: code, Action: action, ReceivedUTC: received.UTC(), Kind: "unknown", Class: "unknown", Evidence: "unclassified"}
	for _, field := range []struct {
		name string
		dest *json.Number
	}{{"UTC", &event.DeviceUTC}, {"RealUTC", &event.DeviceRealUTC}} {
		if value, present := data[field.name]; present {
			number, ok := numberText(value)
			if !ok {
				return Event{}, errors.New("event timestamp is invalid")
			}
			*field.dest = number
		}
	}
	if value, present := data["LocaleTime"]; present {
		text, ok := value.(string)
		if !ok || !validText(text, maxFieldBytes) {
			return Event{}, errors.New("event local timestamp is invalid")
		}
		event.LocaleTime = text
	}
	if value, present := data["event"]; present {
		safe, err := copyField(value)
		if err != nil {
			return Event{}, err
		}
		event.Discriminator = safe
	}
	for _, name := range []string{"RuleID", "RuleId", "Rule", "WindowId", "RegionID"} {
		if value, present := data[name]; present {
			safe, err := copyField(value)
			if err != nil {
				return Event{}, err
			}
			if event.RuleIDs == nil {
				event.RuleIDs = make(map[string]any)
			}
			event.RuleIDs[name] = safe
		}
	}
	objectTypes(data, &event.ObjectTypes)
	if object, ok := data["Object"].(map[string]any); ok {
		objectTypes(object, &event.ObjectTypes)
	}
	if objects, ok := data["object"].([]any); ok {
		for _, object := range objects {
			if value, ok := object.(map[string]any); ok {
				objectTypes(value, &event.ObjectTypes)
			}
		}
	}
	switch code {
	case "VideoMotion":
		event.Kind, event.Evidence = "motion", "native_code"
	case "SmartMotionHuman":
		event.Kind, event.Class, event.Evidence = "smart_motion", "human", "native_code"
	case "SmartMotionVehicle":
		event.Kind, event.Class, event.Evidence = "smart_motion", "vehicle", "native_code"
	case CodePetMotion:
		event.Kind, event.Class, event.Evidence = "smart_motion", "pet", "native_code"
	case "CrossLineDetection":
		event.Kind, event.Evidence = "line_crossing", "native_code"
		classifyIVS(&event)
	case "CrossRegionDetection":
		event.Kind, event.Evidence = "intrusion", "native_code"
		classifyIVS(&event)
	case "VideoBlind":
		event.Kind, event.Evidence = "tamper", "native_code"
	case "Intelligent":
		event.Kind = "intelligent"
		for _, mapping := range mappings {
			if mapping.DeviceID == deviceID && mapping.SourceIndex == index && mapping.Code == code && discriminatorText(event.Discriminator) == mapping.Discriminator {
				event.Class, event.Evidence = mapping.Class, "operator_correlated"
			}
		}
	}
	return event, nil
}

// classifyIVS derives a stable class set from explicit object labels; mixed classes leave
// the singular Class unknown.
func classifyIVS(event *Event) {
	classes := make(map[string]bool)
	for _, label := range event.ObjectTypes {
		switch strings.ToLower(strings.TrimSpace(label)) {
		case "human":
			classes["human"] = true
		case "vehicle":
			classes["vehicle"] = true
		case "pet", "animal":
			classes["pet"] = true
		}
	}
	for _, class := range []string{"human", "vehicle", "pet"} {
		if classes[class] {
			event.Classes = append(event.Classes, class)
		}
	}
	if len(event.Classes) != 0 {
		event.Evidence = "native_object"
	}
	if len(event.Classes) == 1 {
		event.Class = event.Classes[0]
	}
}

// validateMappings rejects unbounded, unscoped, or duplicate Intelligent-event overrides
// before any payload is interpreted.
func validateMappings(mappings []Mapping) error {
	if len(mappings) > 256 {
		return errors.New("event mappings exceed limit")
	}
	seen := make(map[string]bool)
	for _, mapping := range mappings {
		if mapping.DeviceID == "" || !validText(mapping.DeviceID, maxFieldBytes) || mapping.SourceIndex < 0 || mapping.SourceIndex > 65535 || mapping.Code != "Intelligent" || mapping.Discriminator == "" || !validText(mapping.Discriminator, maxFieldBytes) || (mapping.Class != "human" && mapping.Class != "vehicle" && mapping.Class != "pet") {
			return errors.New("event mapping is invalid")
		}
		key := fmt.Sprintf("%s\x00%d\x00%s\x00%s", mapping.DeviceID, mapping.SourceIndex, mapping.Code, mapping.Discriminator)
		if seen[key] {
			return errors.New("event mappings are ambiguous")
		}
		seen[key] = true
	}
	return nil
}

// first returns the first present spelling of a native field, including an explicitly null value.
func first(object map[string]any, names ...string) any {
	for _, name := range names {
		if value, present := object[name]; present {
			return value
		}
	}
	return nil
}

// validText bounds text by bytes and rejects Unicode control characters before fields enter normalized events.
func validText(value string, limit int) bool {
	return len(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

// numberText accepts finite JSON-compatible numeric values while preserving an existing number spelling.
func numberText(value any) (json.Number, bool) {
	var text string
	switch number := value.(type) {
	case json.Number:
		text = number.String()
	case string:
		text = number
	case float64:
		text = strconv.FormatFloat(number, 'f', -1, 64)
	case int:
		text = strconv.Itoa(number)
	case int64:
		text = strconv.FormatInt(number, 10)
	default:
		return "", false
	}
	if len(text) > 64 || !json.Valid([]byte(text)) {
		return "", false
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return "", false
	}
	return json.Number(text), true
}

// discriminatorText reduces supported string and numeric discriminators to the exact text
// used by operator mappings.
func discriminatorText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if number, ok := numberText(value); ok {
		return number.String()
	}
	return ""
}

// objectTypes appends at most 64 unique, bounded native class labels without interpreting them.
func objectTypes(object map[string]any, result *[]string) {
	add := func(value any) {
		if text, ok := value.(string); ok && text != "" && validText(text, maxFieldBytes) && len(*result) < 64 {
			for _, existing := range *result {
				if existing == text {
					return
				}
			}
			*result = append(*result, text)
		}
	}
	for _, field := range []string{"ObjectType", "Class"} {
		add(object[field])
	}
	if values, ok := object["ObjectTypes"].([]any); ok {
		for _, value := range values {
			add(value)
		}
	}
}

// decodeObject accepts one bounded JSON object and applies the same structural checks to already decoded values.
func decodeObject(payload any) (map[string]any, error) {
	var encoded []byte
	switch value := payload.(type) {
	case []byte:
		encoded = value
	case json.RawMessage:
		encoded = value
	case string:
		if len(value) > maxPayloadBytes {
			return nil, errors.New("event payload exceeds limit")
		}
		encoded = []byte(value)
	default:
		nodes, size := 0, 0
		if err := checkValue(value, 0, &nodes, &size); err != nil {
			return nil, err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("event payload is not an object")
		}
		return object, nil
	}
	if len(encoded) > maxPayloadBytes {
		return nil, errors.New("event payload exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("event payload JSON is invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("event payload contains trailing JSON")
	}
	return decodeObject(value)
}

// checkValue bounds depth, node count, and estimated payload size while rejecting
// unsupported Go values and nonfinite numbers.
func checkValue(value any, depth int, nodes, size *int) error {
	*nodes++
	*size += 8
	if depth > maxDepth || *nodes > maxNodes || *size > maxPayloadBytes {
		return errors.New("event payload exceeds structural limit")
	}
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			*size += len(key)
			if err := checkValue(child, depth+1, nodes, size); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := checkValue(child, depth+1, nodes, size); err != nil {
				return err
			}
		}
	case string:
		*size += len(value)
	case json.Number:
		if _, ok := numberText(value); !ok {
			return errors.New("event payload number is invalid")
		}
	case nil, bool, int, int64:
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("event payload number is invalid")
		}
	default:
		return errors.New("event payload type is unsupported")
	}
	if *size > maxPayloadBytes {
		return errors.New("event payload exceeds size limit")
	}
	return nil
}

// copyField bounds selected unknown discriminator/rule values and strips secret
// field names recursively. The rest of the native payload is never exported.
func copyField(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 4096 {
		return nil, errors.New("event field exceeds limit or is invalid")
	}
	return safeCopy(value), nil
}

// safeCopy clones nested maps and lists while omitting secret-bearing fields from retained
// discriminator and rule metadata.
func safeCopy(value any) any {
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any)
		for key, child := range value {
			if sensitiveField(key) {
				continue
			}
			result[key] = safeCopy(child)
		}
		return result
	case []any:
		result := make([]any, len(value))
		for index, child := range value {
			result[index] = safeCopy(child)
		}
		return result
	default:
		return value
	}
}

// sensitiveField normalizes punctuation and case before recognizing secret-bearing metadata keys.
func sensitiveField(key string) bool {
	name := strings.Map(func(value rune) rune {
		if unicode.IsLetter(value) || unicode.IsDigit(value) {
			return unicode.ToLower(value)
		}
		return -1
	}, key)
	if name == "key" || name == "pass" {
		return true
	}
	for _, sensitive := range []string{"password", "passwd", "pwd", "secret", "token", "session", "auth", "credential", "privatekey", "apikey"} {
		if strings.Contains(name, sensitive) {
			return true
		}
	}
	return false
}
