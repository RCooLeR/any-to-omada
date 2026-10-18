package omadafront

import (
	"bytes"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// virtualTimeState holds only this virtual camera's presentation settings and
// clock offset. It never sets the host clock or sends a physical-camera request.
type virtualTimeState struct {
	// mu guards offset and configuration; no I/O occurs while it is held.
	mu     sync.Mutex
	now    func() time.Time
	offset time.Duration
	basic  map[string]any
	dst    map[string]any
}

func newVirtualTimeState(now func() time.Time) *virtualTimeState {
	return &virtualTimeState{now: now,
		basic: map[string]any{"timezone": "UTC+00:00", "zone_id": "Etc/UTC", "date_format": 0, "time_format": 0},
		dst: map[string]any{"enabled": "off", "dst_savings": "60", "start_month": "3", "start_week": "5", "start_day": "0", "start_hour": "3",
			"end_month": "10", "end_week": "5", "end_day": "0", "end_hour": "4"},
	}
}

func (s *virtualTimeState) read(name string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case "basic":
		return copyTimeFields(s.basic), true
	case "dst_manual":
		return copyTimeFields(s.dst), true
	case "time_status":
		now := s.now().Add(s.offset)
		return map[string]any{"seconds_from_1970": now.Unix(), "u_seconds": now.Nanosecond() / 1000}, true
	default:
		return nil, false
	}
}

func copyTimeFields(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

// write accepts only the captured system configuration and clock operations.
// The entire request is validated before any virtual state changes.
func (s *virtualTimeState) write(method string, request map[string]json.RawMessage) bool {
	if len(request) != 2 {
		return false
	}
	var system map[string]json.RawMessage
	if json.Unmarshal(request["system"], &system) != nil || len(system) == 0 {
		return false
	}
	switch method {
	case "set":
		return s.configure(system)
	case "do":
		if len(system) != 1 {
			return false
		}
		return s.setClock(system["set_time"])
	default:
		return false
	}
}

var virtualTimezonePattern = regexp.MustCompile(`^UTC[+-](0[0-9]|1[0-4]):[0-5][0-9]$`)
var virtualZoneIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+.-]{0,63}(?:/[A-Za-z0-9_+.-]{1,64}){0,3}$`)

func (s *virtualTimeState) configure(system map[string]json.RawMessage) bool {
	updates := make(map[string]map[string]any, len(system))
	for section, raw := range system {
		if section != "basic" && section != "dst_manual" {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
			return false
		}
		values := make(map[string]any, len(fields))
		for key, value := range fields {
			parsed, ok := parseTimeConfig(section, key, value)
			if !ok {
				return false
			}
			values[key] = parsed
		}
		updates[section] = values
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for section, values := range updates {
		destination := s.basic
		if section == "dst_manual" {
			destination = s.dst
		}
		for key, value := range values {
			destination[key] = value
		}
	}
	return true
}

func parseTimeConfig(section, key string, raw json.RawMessage) (any, bool) {
	var text string
	if section == "basic" {
		switch key {
		case "timezone":
			ok := json.Unmarshal(raw, &text) == nil && virtualTimezonePattern.MatchString(text)
			// Fourteen hours is the largest supported civil UTC offset.
			return text, ok && (text[4:6] != "14" || text[7:] == "00")
		case "zone_id":
			return textValue(raw, virtualZoneIDPattern)
		case "date_format":
			value, ok := timeConfigInteger(raw, 0, 2)
			return int(value), ok
		case "time_format":
			value, ok := timeConfigInteger(raw, 0, 1)
			return int(value), ok
		default:
			return nil, false
		}
	}
	if key == "enabled" {
		ok := json.Unmarshal(raw, &text) == nil && (text == "on" || text == "off")
		return text, ok
	}
	minimum, maximum := int64(0), int64(0)
	switch key {
	case "dst_savings":
		minimum, maximum = 0, 180
	case "start_month", "end_month":
		minimum, maximum = 1, 12
	case "start_week", "end_week":
		minimum, maximum = 1, 5
	case "start_day", "end_day":
		minimum, maximum = 0, 6
	case "start_hour", "end_hour":
		minimum, maximum = 0, 23
	default:
		return nil, false
	}
	value, ok := timeConfigInteger(raw, minimum, maximum)
	// Captured SET uses integers; the donor's GET serializes DST values as strings.
	return strconv.FormatInt(value, 10), ok
}

func textValue(raw json.RawMessage, pattern *regexp.Regexp) (string, bool) {
	var value string
	ok := json.Unmarshal(raw, &value) == nil && pattern.MatchString(value)
	return value, ok
}

func timeConfigInteger(raw json.RawMessage, minimum, maximum int64) (int64, bool) {
	var value int64
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return 0, false
	}
	return value, value >= minimum && value <= maximum
}

func (s *virtualTimeState) setClock(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 9 {
		return false
	}
	var priority, sourceMAC string
	if json.Unmarshal(fields["source_time_priority"], &priority) != nil || priority != "NVR_NTP" ||
		json.Unmarshal(fields["source_mac"], &sourceMAC) != nil {
		return false
	}
	mac, err := net.ParseMAC(sourceMAC)
	if err != nil || len(mac) != 6 {
		return false
	}
	if _, ok := timeConfigInteger(fields["transmit"], 0, 0); !ok {
		return false
	}
	timestamps := [3]int64{}
	for index, prefix := range []string{"T1_timestramp", "T2_timestramp", "T3_timestramp"} {
		seconds, ok := timeConfigInteger(fields[prefix], 946684800, 4102444800)
		if !ok {
			return false
		}
		micros, ok := timeConfigInteger(fields[prefix+"_u"], 0, 999999)
		if !ok {
			return false
		}
		timestamps[index] = seconds*1_000_000 + micros
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t4 := s.now().Add(s.offset).UnixMicro()
	t1, t2, t3 := timestamps[0], timestamps[1], timestamps[2]
	// T1/T4 are camera instants and T2/T3 are recorder instants. Keep the
	// bounded exchange fresh and ordered before changing this virtual clock.
	if t4 < t1 || t4-t1 > 10_000_000 || t3 < t2 || t3-t2 > 10_000_000 {
		return false
	}
	// Recovered from the donor's system.set_time handler. The correction is
	// ((T2-T1)+(T3-T4))/2, not simply the third timestamp as an absolute date.
	correction := ((t2 - t1) + (t3 - t4)) / 2
	s.offset += time.Duration(correction) * time.Microsecond
	return true
}
