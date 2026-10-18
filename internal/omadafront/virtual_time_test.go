package omadafront

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func timeWrite(t *testing.T, state *virtualTimeState, raw string) bool {
	t.Helper()
	var request map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatal(err)
	}
	var method string
	if err := json.Unmarshal(request["method"], &method); err != nil {
		t.Fatal(err)
	}
	return state.write(method, request)
}

func timeSection(t *testing.T, state *virtualTimeState, name string) map[string]any {
	t.Helper()
	value, ok := state.read(name)
	if !ok {
		t.Fatal("expected virtual time section is missing")
	}
	return value.(map[string]any)
}

func clockWrite(t *testing.T, state *virtualTimeState, t1, t2, t3 time.Time) bool {
	t.Helper()
	fields := map[string]any{"source_time_priority": "NVR_NTP", "source_mac": "02-00-00-00-00-01", "transmit": 0}
	for index, prefix := range []string{"T1_timestramp", "T2_timestramp", "T3_timestramp"} {
		instant := []time.Time{t1, t2, t3}[index]
		fields[prefix], fields[prefix+"_u"] = instant.Unix(), instant.Nanosecond()/1000
	}
	raw, err := json.Marshal(map[string]any{"method": "do", "system": map[string]any{"set_time": fields}})
	if err != nil {
		t.Fatal(err)
	}
	return timeWrite(t, state, string(raw))
}

func TestVirtualTimeConfigurationRoundTripAndIdempotence(t *testing.T) {
	state := newVirtualTimeState(time.Now)
	const configuration = `{"method":"set","system":{"basic":{"timezone":"UTC+02:00","zone_id":"Europe/Vilnius","date_format":1,"time_format":0},"dst_manual":{"enabled":"on","dst_savings":60,"start_month":3,"start_week":5,"start_day":0,"start_hour":3,"end_month":10,"end_week":5,"end_day":0,"end_hour":4}}}`
	for range 2 {
		if !timeWrite(t, state, configuration) {
			t.Fatal("captured virtual configuration was rejected")
		}
	}
	basic := timeSection(t, state, "basic")
	wantBasic := map[string]any{"timezone": "UTC+02:00", "zone_id": "Europe/Vilnius", "date_format": 1, "time_format": 0}
	if !reflect.DeepEqual(basic, wantBasic) {
		t.Fatalf("stored basic configuration = %#v", basic)
	}
	dst := timeSection(t, state, "dst_manual")
	if dst["enabled"] != "on" || dst["dst_savings"] != "60" || dst["start_month"] != "3" || dst["end_hour"] != "4" {
		t.Fatal("DST readback lost values or donor numeric-string types")
	}
	// Returned maps cannot mutate the virtual camera's internal state.
	basic["timezone"], dst["enabled"] = "invalid", "invalid"
	if timeSection(t, state, "basic")["timezone"] != "UTC+02:00" || timeSection(t, state, "dst_manual")["enabled"] != "on" {
		t.Fatal("readback exposed mutable state")
	}
}

func TestVirtualTimeRejectsMalformedSettingsAtomically(t *testing.T) {
	state := newVirtualTimeState(time.Now)
	beforeBasic, beforeDST := timeSection(t, state, "basic"), timeSection(t, state, "dst_manual")
	for _, raw := range []string{
		`{"method":"set","system":{"basic":{"timezone":"UTC+02:00"},"dst_manual":{"enabled":"on","end_month":13}}}`,
		`{"method":"set","system":{"basic":{"date_format":1,"unknown":"value"}}}`,
		`{"method":"set","system":{"basic":{"timezone":"UTC+14:01"}}}`,
		`{"method":"set","system":{"basic":{"timezone":"x"}}}`,
		`{"method":"set","system":{"basic":{"zone_id":"../outside"}}}`,
		`{"method":"set","system":{"basic":{"time_format":null}}}`,
		`{"method":"set","system":{"basic":{"time_format":"0"}}}`,
		`{"method":"set","system":{"basic":{}}}`,
		`{"method":"set","system":{"basic":null}}`,
		`{"method":"set","system":{"ntp":{"server":"example.invalid"}}}`,
		`{"method":"set","system":{"basic":{"date_format":1}},"video":{"main":{}}}`,
		`{"method":"do","system":{"set_date":{"seconds_from_1970":1792100000}}}`,
	} {
		if timeWrite(t, state, raw) {
			t.Fatalf("unsupported or malformed settings accepted: %s", raw)
		}
		if !reflect.DeepEqual(beforeBasic, timeSection(t, state, "basic")) || !reflect.DeepEqual(beforeDST, timeSection(t, state, "dst_manual")) {
			t.Fatal("failed multi-section write changed part of the configuration")
		}
	}
}

func TestVirtualTimeUsesFourTimestampCorrectionAndProgresses(t *testing.T) {
	for _, offset := range []time.Duration{-90 * time.Second, 0, 90*time.Second + 250*time.Millisecond} {
		t.Run(offset.String(), func(t *testing.T) {
			start := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
			now := start.Add(300 * time.Millisecond)
			state := newVirtualTimeState(func() time.Time { return now })
			// Symmetric 100 ms network legs and 100 ms recorder processing.
			if !clockWrite(t, state, start, start.Add(offset+100*time.Millisecond), start.Add(offset+200*time.Millisecond)) {
				t.Fatal("valid recorder time exchange rejected")
			}
			if state.offset != offset {
				t.Fatalf("clock offset = %s, want %s", state.offset, offset)
			}
			now = now.Add(2 * time.Second)
			want := now.Add(offset)
			clock := timeSection(t, state, "time_status")
			if clock["seconds_from_1970"] != want.Unix() || clock["u_seconds"] != want.Nanosecond()/1000 {
				t.Fatal("virtual clock did not advance with the host clock")
			}
			// Re-synchronization uses the existing virtual offset, not host time.
			t1 := want
			now = now.Add(300 * time.Millisecond)
			if !clockWrite(t, state, t1, t1.Add(100*time.Millisecond), t1.Add(200*time.Millisecond)) || state.offset != offset {
				t.Fatal("repeated synchronization added the existing offset twice")
			}
			other := newVirtualTimeState(func() time.Time { return now })
			if timeSection(t, other, "time_status")["seconds_from_1970"] != now.Unix() {
				t.Fatal("one camera's offset affected another virtual camera")
			}
		})
	}
}

func TestVirtualTimeRejectsStaleOrReversedClockExchange(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	state := newVirtualTimeState(func() time.Time { return now })
	for _, instants := range [][3]time.Time{
		{now.Add(-11 * time.Second), now, now},
		{now.Add(time.Second), now, now},
		{now, now, now.Add(-time.Second)},
		{now, now, now.Add(11 * time.Second)},
	} {
		if clockWrite(t, state, instants[0], instants[1], instants[2]) || state.offset != 0 {
			t.Fatal("stale or reversed clock exchange changed state")
		}
	}
}

func TestVirtualTimeClockRequiresExactCapturedSchema(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	state := newVirtualTimeState(func() time.Time { return now })
	base := map[string]any{"source_time_priority": "NVR_NTP", "source_mac": "02-00-00-00-00-01", "transmit": 0,
		"T1_timestramp": now.Unix(), "T1_timestramp_u": 0, "T2_timestramp": now.Unix(), "T2_timestramp_u": 0, "T3_timestramp": now.Unix(), "T3_timestramp_u": 0}
	for _, change := range []struct {
		key   string
		value any
	}{
		{"source_time_priority", "OTHER"}, {"source_mac", "invalid"}, {"transmit", 1}, {"transmit", nil},
		{"T1_timestramp_u", 1_000_000}, {"T2_timestramp", -1}, {"T3_timestramp", 1e100}, {"T3_timestramp_u", 0.5}, {"extra", 1},
	} {
		fields := copyTimeFields(base)
		fields[change.key] = change.value
		raw, err := json.Marshal(map[string]any{"method": "do", "system": map[string]any{"set_time": fields}})
		if err != nil {
			t.Fatal(err)
		}
		if timeWrite(t, state, string(raw)) || state.offset != 0 {
			t.Fatalf("invalid clock field %s changed state", change.key)
		}
	}
}
