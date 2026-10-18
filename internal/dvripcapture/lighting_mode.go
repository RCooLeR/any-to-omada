package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LightingModeSettings is a physical configuration readback for the verified
// fixed active source profile. Scheme and modes retain native vocabulary.
type LightingModeSettings struct {
	Scheme       string
	WhiteMode    string
	InfraredMode string
	Brightness   int
}

// LightingChange addresses optional native fields in one validated operation.
// Empty strings and nil Brightness preserve existing settings. Brightness always
// means the white-light bank percentage in 0..100, independently of the scheme.
type LightingChange struct {
	Scheme       string
	WhiteMode    string
	InfraredMode string
	Brightness   *int
}

// lightingModeSnapshot holds selected source fields and advertised mode lists.
// It never contains account, image, OSD or network configuration.
type lightingModeSnapshot struct {
	settings LightingModeSettings
	values   map[string]any
	white    string
	infrared string
	bank     string
	scheme   string
	modes    map[string]any
	schemes  []any
	tables   map[string][]any
	targets  map[string]lightingFieldTarget
}

// lightingFieldTarget points into one fresh native table for a narrow mutation.
type lightingFieldTarget struct {
	entry map[string]any
	key   string
}

// lightingField records one addressed configuration mutation and its original
// scalar. attempted includes a lost acknowledgement that may have applied.
type lightingField struct {
	name      string
	before    any
	after     any
	attempted bool
}

// LightingLease restores only fields this operation changed and still owns.
// Calls are serialized internally; callers must also serialize separate leases
// and other output operations for the same physical source. There is no timer:
// the owner must restore on cancellation, timeout and shutdown.
type LightingLease struct {
	lighting    *Lighting
	channel     int
	profile     int
	fields      []lightingField
	gate        chan struct{}
	beforeWrite func()
}

// ModeSettings reads source settings and verifies explicit white-light modes,
// a physical brightness bank and a fixed active profile. Generic WhiteLight
// configuration entries alone do not establish supported hardware.
func (l *Lighting) ModeSettings(ctx context.Context, channel, profile int) (settings LightingModeSettings, result error) {
	result = l.session(ctx, func(call lightingCall) error {
		snapshot, err := lightingModeSnapshotRead(ctx, call, channel, profile, true)
		if err == nil {
			settings = snapshot.settings
		}
		return err
	})
	return settings, result
}

// ManualAvailable validates the real white-light contract without writing.
func (l *Lighting) ManualAvailable(ctx context.Context, channel, profile int) error {
	_, err := l.ModeSettings(ctx, channel, profile)
	return err
}

// Acquire applies a verified manual white-light override and returns its
// restoration lease. On an uncertain failure, the non-nil lease is retained
// even if immediate cleanup fails; its owner must retry Restore or report the
// final configuration as unconfirmed. No activation write is retried.
func (l *Lighting) Acquire(ctx context.Context, channel, profile, brightness int) (*LightingLease, error) {
	if brightness < 1 || brightness > 100 {
		return nil, ErrLightingUnsupported
	}
	return l.applyMode(ctx, channel, profile, "WhiteMode", "Manual", brightness)
}

// ManualPulse uses the recorder illumination contract for a temporary test,
// then restores the original source policy even after caller cancellation.
// Its duration starts at the first attempted write, including response and
// readback time. Expiry cancels acquisition and begins independent restoration.
// It is separate from the legacy Lighting_V2-only experimental Pulse method.
func (l *Lighting) ManualPulse(ctx context.Context, channel, profile, brightness int, duration time.Duration) (result error) {
	if brightness < 1 || brightness > 100 || duration < 100*time.Millisecond || duration > 5*time.Second {
		return ErrLightingUnsupported
	}
	request, cancel := context.WithCancel(ctx)
	expired := make(chan struct{})
	var timer *time.Timer
	defer func() {
		cancel()
		if timer != nil && !timer.Stop() {
			<-expired
		}
	}()
	startDeadline := func() {
		timer = time.AfterFunc(duration, func() {
			cancel()
			close(expired)
		})
	}
	change := LightingChange{Scheme: "WhiteMode", WhiteMode: "Manual", Brightness: &brightness}
	lease, err := l.applyLightingChange(request, channel, profile, change, startDeadline)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		result = errors.Join(result, lease.Restore(cleanup))
	}()
	if timer == nil {
		return nil // The requested settings already existed; no override was applied.
	}
	select {
	case <-expired:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetMode intentionally persists an advertised illumination policy for the
// fixed active profile, changing only addressed lighting fields. WhiteMode and
// InfraredMode require an advertised lamp mode. AIMode preserves its existing
// source detection policy and requires an empty mode. Failed partial writes are
// rolled back; uncertain rollback is returned as ErrLightingRestore.
func (l *Lighting) SetMode(ctx context.Context, channel, profile int, scheme, mode string, brightness int) error {
	_, err := l.applyMode(ctx, channel, profile, scheme, mode, brightness)
	return err
}

// ApplyMode validates every requested field before changing any setting and
// persists the result only after readback. Partial failures attempt restoration.
func (l *Lighting) ApplyMode(ctx context.Context, channel, profile int, change LightingChange) error {
	_, err := l.applyLightingChange(ctx, channel, profile, change, nil)
	return err
}

// applyMode reads capabilities and current values before any write, then checks
// exact readback. The returned lease owns only fields whose value changed.
func (l *Lighting) applyMode(ctx context.Context, channel, profile int, scheme, mode string, brightness int) (lease *LightingLease, result error) {
	change := LightingChange{Scheme: scheme}
	switch scheme {
	case "WhiteMode":
		if mode == "" {
			return nil, ErrLightingUnsupported
		}
		change.WhiteMode = mode
		if mode == "Manual" {
			change.Brightness = &brightness
		}
	case "InfraredMode":
		if mode == "" {
			return nil, ErrLightingUnsupported
		}
		change.InfraredMode = mode
	case "AIMode":
		if mode != "" {
			return nil, ErrLightingUnsupported
		}
	default:
		return nil, ErrLightingUnsupported
	}
	return l.applyLightingChange(ctx, channel, profile, change, nil)
}

// applyLightingChange shares the transactional field path with temporary leases.
func (l *Lighting) applyLightingChange(ctx context.Context, channel, profile int, change LightingChange, beforeWrite func()) (lease *LightingLease, result error) {
	if channel < 0 || channel > 65535 || profile < 0 || profile > 7 {
		return nil, ErrLightingUnsupported
	}
	result = l.session(ctx, func(call lightingCall) error {
		snapshot, err := lightingModeSnapshotRead(ctx, call, channel, profile, true)
		if err != nil {
			return err
		}
		if change.Scheme != "" && ((change.Scheme != "WhiteMode" && change.Scheme != "InfraredMode" && change.Scheme != "AIMode") || !lightingContains(snapshot.schemes, change.Scheme)) {
			return ErrLightingUnsupported
		}
		if change.WhiteMode != "" && !lightingModeAdvertised(snapshot.modes, "WhiteLight", change.WhiteMode) {
			return ErrLightingUnsupported
		}
		if change.InfraredMode != "" && (snapshot.infrared == "" || !lightingModeAdvertised(snapshot.modes, "InfraredLight", change.InfraredMode)) {
			return ErrLightingUnsupported
		}
		if change.Brightness != nil && (*change.Brightness < 0 || *change.Brightness > 100) {
			return ErrLightingUnsupported
		}
		changes := []lightingField{}
		add := func(name string, after any) {
			before, exists := snapshot.values[name]
			if exists && !lightingScalarEqual(before, after) {
				changes = append(changes, lightingField{name: name, before: before, after: after})
			}
		}
		if change.Brightness != nil {
			add(snapshot.bank, *change.Brightness)
		}
		if change.WhiteMode != "" {
			add(snapshot.white, change.WhiteMode)
		}
		if change.InfraredMode != "" {
			add(snapshot.infrared, change.InfraredMode)
		}
		// Apply the scheme last, after the target lamp has its desired fields.
		if change.Scheme != "" {
			add(snapshot.scheme, change.Scheme)
		}
		lease = &LightingLease{lighting: l, channel: channel, profile: profile, fields: changes, gate: make(chan struct{}, 1), beforeWrite: beforeWrite}
		for _, group := range []string{"Lighting_V2", "LightingScheme"} {
			if err := lease.writeGroup(ctx, call, group, false); err != nil {
				return err
			}
		}
		current, err := lightingModeSnapshotRead(ctx, call, channel, profile, false)
		if err != nil {
			return err
		}
		for _, field := range lease.fields {
			if !lightingScalarEqual(current.values[field.name], field.after) {
				return lightingFailure("configManager.setConfig", "readback_mismatch", nil)
			}
		}
		return nil
	})
	if result != nil && lease != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		result = errors.Join(result, lease.Restore(cleanup))
	}
	return lease, result
}

// Restore re-reads before restoring the owned scalars, preserving unrelated
// settings and changes by other controllers. Successful restoration is verified
// from a separate readback; the method is safe to call again after success.
func (l *LightingLease) Restore(ctx context.Context) error {
	select {
	case l.gate <- struct{}{}:
	case <-ctx.Done():
		return errors.Join(ErrLightingRestore, ctx.Err())
	}
	defer func() { <-l.gate }()
	err := l.lighting.session(ctx, func(call lightingCall) error {
		var failures []error
		for _, group := range []string{"LightingScheme", "Lighting_V2"} {
			if err := l.writeGroup(ctx, call, group, true); err != nil {
				failures = append(failures, err)
			}
		}
		verified, err := lightingModeSnapshotRead(ctx, call, l.channel, l.profile, false)
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		for index := range l.fields {
			field := &l.fields[index]
			if field.attempted {
				if lightingScalarEqual(verified.values[field.name], field.before) {
					field.attempted = false
				} else {
					failures = append(failures, errors.New("native lighting restore readback mismatch"))
				}
			}
		}
		return errors.Join(failures...)
	})
	if err != nil {
		return errors.Join(ErrLightingRestore, err)
	}
	return nil
}

// writeGroup follows the camera UI's full-table RPC contract. A fresh read
// preserves other channels and profiles, while selected field comparisons
// prevent replaying stale values after another controller changed them.
func (l *LightingLease) writeGroup(ctx context.Context, call lightingCall, group string, restore bool) error {
	needed := false
	for _, field := range l.fields {
		if strings.HasPrefix(field.name, group+"[") && (!restore || field.attempted) {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	current, err := lightingModeSnapshotRead(ctx, call, l.channel, l.profile, false)
	if err != nil {
		return err
	}
	var changed []int
	var failures []error
	for index := range l.fields {
		field := &l.fields[index]
		if !strings.HasPrefix(field.name, group+"[") || (restore && !field.attempted) {
			continue
		}
		expected, desired := field.before, field.after
		if restore {
			expected, desired = field.after, field.before
			if lightingScalarEqual(current.values[field.name], desired) {
				field.attempted = false
				continue
			}
		}
		target, exists := current.targets[field.name]
		if !exists || !lightingScalarEqual(current.values[field.name], expected) {
			failures = append(failures, lightingFailure("configManager.setConfig", "ownership_changed", nil))
			continue
		}
		target.entry[target.key] = desired
		changed = append(changed, index)
	}
	if len(failures) != 0 && !restore {
		return errors.Join(failures...)
	}
	if len(changed) != 0 {
		for _, index := range changed {
			l.fields[index].attempted = true
		}
		if !restore && l.beforeWrite != nil {
			l.beforeWrite()
			l.beforeWrite = nil
		}
		_, err := call(ctx, "configManager.setConfig", map[string]any{"name": group, "table": current.tables[group], "options": []any{}})
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// State reads whether this lease's active override still matches the source.
// A restored lease reports false; mixed or foreign settings return an error.
func (l *LightingLease) State(ctx context.Context) (active bool, result error) {
	select {
	case l.gate <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-l.gate }()
	result = l.lighting.session(ctx, func(call lightingCall) error {
		current, err := lightingModeSnapshotRead(ctx, call, l.channel, l.profile, false)
		if err != nil {
			return err
		}
		for _, field := range l.fields {
			if field.attempted {
				if !lightingScalarEqual(current.values[field.name], field.after) {
					return ErrLightingRestore
				}
				active = true
			}
		}
		return nil
	})
	return active, result
}

// lightingModeSnapshotRead validates source capabilities only for new writes;
// cleanup must remain possible after capability or active-profile changes.
func lightingModeSnapshotRead(ctx context.Context, call lightingCall, channel, profile int, validate bool) (lightingModeSnapshot, error) {
	snapshot := lightingModeSnapshot{values: map[string]any{}, targets: map[string]lightingFieldTarget{}, tables: map[string][]any{}}
	if channel < 0 || channel > 65535 || profile < 0 || profile > 7 {
		return snapshot, ErrLightingUnsupported
	}
	if validate {
		answer, err := call(ctx, "magicBox.getProductDefinition", nil)
		if err != nil {
			return snapshot, err
		}
		params, _ := answer["params"].(map[string]any)
		definition, _ := params["definition"].(map[string]any)
		caps, _ := definition["LightingControl"].(map[string]any)
		lights, _ := caps["LightTypeComplex"].([]any)
		mix, _ := caps["MixLightSolution"].(map[string]any)
		snapshot.schemes, _ = mix["LightingScheme"].([]any)
		snapshot.modes, _ = caps["ModesComplex"].(map[string]any)
		if snapshot.modes == nil {
			snapshot.modes, _ = caps["ModeListComplex"].(map[string]any)
		}
		if caps["Support"] != true || !lightingContains(lights, "WhiteLight") || !lightingContains(snapshot.schemes, "WhiteMode") || !lightingModeAdvertised(snapshot.modes, "WhiteLight", "Manual") {
			return snapshot, ErrLightingUnsupported
		}
		if err := lightingActiveProfile(ctx, call, channel, profile); err != nil {
			return snapshot, err
		}
	}
	full, err := lightingFullTable(ctx, call, "Lighting_V2")
	if err != nil {
		return snapshot, err
	}
	if channel >= len(full) {
		return snapshot, ErrLightingUnsupported
	}
	table, ok := full[channel].([]any)
	if !ok || len(table) > 8 {
		return snapshot, ErrLightingUnsupported
	}
	snapshot.tables["Lighting_V2"] = full
	white, err := whiteLightEntry(table, profile)
	if err != nil {
		return snapshot, err
	}
	entries := table[profile].([]any)
	for index, item := range entries {
		entry := item.(map[string]any)
		prefix := fmt.Sprintf("Lighting_V2[%d][%d][%d]", channel, profile, index)
		switch entry["LightType"] {
		case "WhiteLight":
			snapshot.white = prefix + ".Mode"
			snapshot.settings.WhiteMode = white["Mode"].(string)
			snapshot.values[snapshot.white] = white["Mode"]
			snapshot.targets[snapshot.white] = lightingFieldTarget{entry: white, key: "Mode"}
			for _, bank := range []string{"NearLight", "MiddleLight", "FarLight"} {
				items, exists := white[bank].([]any)
				if !exists || len(items) == 0 {
					continue
				}
				if len(items) != 1 || snapshot.bank != "" {
					return snapshot, ErrLightingUnsupported
				}
				fields, _ := items[0].(map[string]any)
				brightness, ok := brightnessValue(fields["Light"])
				if !ok {
					return snapshot, ErrLightingUnsupported
				}
				snapshot.bank = prefix + "." + bank + "[0].Light"
				snapshot.values[snapshot.bank] = fields["Light"]
				snapshot.targets[snapshot.bank] = lightingFieldTarget{entry: fields, key: "Light"}
				snapshot.settings.Brightness = brightness
			}
		case "InfraredLight":
			mode, ok := entry["Mode"].(string)
			if !ok || snapshot.infrared != "" {
				return snapshot, ErrLightingUnsupported
			}
			snapshot.infrared = prefix + ".Mode"
			snapshot.values[snapshot.infrared] = mode
			snapshot.targets[snapshot.infrared] = lightingFieldTarget{entry: entry, key: "Mode"}
			snapshot.settings.InfraredMode = mode
		}
	}
	if snapshot.bank == "" {
		return snapshot, ErrLightingUnsupported
	}
	fullSchemes, err := lightingFullTable(ctx, call, "LightingScheme")
	if err != nil {
		return snapshot, err
	}
	if channel >= len(fullSchemes) {
		return snapshot, ErrLightingUnsupported
	}
	schemes, _ := fullSchemes[channel].([]any)
	if profile < 0 || profile >= len(schemes) || len(schemes) > 8 {
		return snapshot, ErrLightingUnsupported
	}
	entry, _ := schemes[profile].(map[string]any)
	scheme, ok := entry["LightingMode"].(string)
	if !ok || (scheme != "WhiteMode" && scheme != "InfraredMode" && scheme != "AIMode") {
		return snapshot, ErrLightingUnsupported
	}
	snapshot.scheme = fmt.Sprintf("LightingScheme[%d][%d].LightingMode", channel, profile)
	snapshot.values[snapshot.scheme] = scheme
	snapshot.targets[snapshot.scheme] = lightingFieldTarget{entry: entry, key: "LightingMode"}
	snapshot.tables["LightingScheme"] = fullSchemes
	snapshot.settings.Scheme = scheme
	return snapshot, nil
}

// lightingFullTable reads exactly the complete native table that the camera's
// own UI writes. Indexed RPC names are not scalar selectors on these cameras.
func lightingFullTable(ctx context.Context, call lightingCall, name string) ([]any, error) {
	answer, err := call(ctx, "configManager.getConfig", map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	params, _ := answer["params"].(map[string]any)
	table, ok := params["table"].([]any)
	if !ok || len(table) == 0 || len(table) > 64 {
		return nil, ErrLightingUnsupported
	}
	return table, nil
}

// lightingActiveProfile accepts only the measured fixed-profile source mode.
// Scheduled/day-night selection is not guessed from a static profile index.
func lightingActiveProfile(ctx context.Context, call lightingCall, channel, profile int) error {
	answer, err := call(ctx, "configManager.getConfig", map[string]any{"name": "VideoInMode", "channel": channel})
	if err != nil {
		return err
	}
	params, err := lightingChannelParams(answer, channel)
	if err != nil {
		return err
	}
	table, _ := params["table"].(map[string]any)
	profiles, _ := table["Config"].([]any)
	if table["Mode"] != json.Number("0") || len(profiles) != 1 || profiles[0] != json.Number(fmt.Sprint(profile)) {
		return ErrLightingUnsupported
	}
	return nil
}

// lightingChannelParams rejects an echoed channel that differs from the
// selected source lens; absent echoes retain the observed camera contract.
func lightingChannelParams(answer map[string]any, channel int) (map[string]any, error) {
	params, ok := answer["params"].(map[string]any)
	if !ok {
		return nil, ErrLightingUnsupported
	}
	if echoed, present := params["channel"]; present && echoed != json.Number(fmt.Sprint(channel)) {
		return nil, ErrLightingUnsupported
	}
	return params, nil
}

// lightingContains compares literal vendor capability values without coercion.
func lightingContains(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// lightingModeAdvertised requires an explicit per-lamp mode list.
func lightingModeAdvertised(modes map[string]any, lamp, mode string) bool {
	if mode != "Manual" && mode != "Auto" && mode != "Off" {
		return false
	}
	values, _ := modes[lamp].([]any)
	return lightingContains(values, mode)
}

// lightingScalarEqual compares native string modes or integral percentages.
func lightingScalarEqual(a, b any) bool {
	if text, ok := a.(string); ok {
		return text == b
	}
	x, xok := brightnessValue(a)
	y, yok := brightnessValue(b)
	return xok && yok && x == y
}
