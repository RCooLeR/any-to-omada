// Package onvifevents subscribes to a camera's ONVIF event service with a
// PullPoint subscription and turns documented motion, smart-detection, line,
// intrusion and tamper topics into brand-neutral events for the normalizer.
// It only reads: no camera setting is changed.
package onvifevents

import (
	"context"
	"encoding/xml"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/onvifsoap"
)

const protocol = "onvif"

type timings struct {
	pull, termination, renew, request time.Duration
	// idle is the minimum spacing of empty pulls and of retries after a failure.
	idle time.Duration
	// stale closes an interval whose end never arrived.
	stale    time.Duration
	failures int
}

var defaultTimings = timings{pull: 5 * time.Second, termination: 2 * time.Minute, renew: time.Minute, request: 10 * time.Second,
	idle: time.Second, stale: 5 * time.Minute, failures: 3}

// ErrNoEvents means the camera offers no ONVIF event service on this endpoint.
var ErrNoEvents = errors.New("camera has no onvif event service")

// Run subscribes until ctx ends or the subscription fails; the caller
// reconnects. Rejected credentials return capture.ErrAuthentication.
func Run(ctx context.Context, device capture.Device, sink capture.Sink) error {
	return run(ctx, device, sink, defaultTimings)
}

type notification struct {
	Topic   string `xml:"Topic"`
	Message struct {
		Message struct {
			UtcTime           string `xml:"UtcTime,attr"`
			PropertyOperation string `xml:"PropertyOperation,attr"`
			Source            items  `xml:"Source"`
			Data              items  `xml:"Data"`
		} `xml:"Message"`
	} `xml:"Message"`
}

type items struct {
	SimpleItem []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:"Value,attr"`
	} `xml:"SimpleItem"`
}

var itemName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// values keeps at most 32 identifier-named items with bounded values.
func (i items) values() map[string]string {
	result := map[string]string{}
	for _, item := range i.SimpleItem {
		if len(result) == 32 || !itemName.MatchString(item.Name) {
			continue
		}
		value := strings.TrimSpace(item.Value)
		if len(value) > 128 {
			value = value[:128]
		}
		result[item.Name] = value
	}
	return result
}

func run(ctx context.Context, device capture.Device, sink capture.Sink, t timings) (runErr error) {
	client := onvifsoap.New(device.Host, device.NativePort, device.Username, device.Password, t.pull+t.request)
	defer client.Close()
	defer func() {
		if errors.Is(runErr, onvifsoap.ErrAuthentication) {
			runErr = capture.ErrAuthentication
		}
	}()
	setup, cancel := context.WithTimeout(ctx, 3*t.request)
	defer cancel()
	client.SyncClock(setup)
	var info struct{ Manufacturer, Model, FirmwareVersion string }
	if err := client.Call(setup, onvifsoap.DevicePath, onvifsoap.DeviceNamespace, "GetDeviceInformation", "", &info); err != nil {
		return err
	}
	if err := sink.Write(device.ID, protocol, "identity", map[string]any{"manufacturer": clean(info.Manufacturer), "model": clean(info.Model), "firmware": clean(info.FirmwareVersion)}); err != nil {
		return err
	}
	paths, err := client.ServicePaths(setup, onvifsoap.EventsNamespace, onvifsoap.MediaNamespace)
	if err != nil {
		return err
	}
	if paths[onvifsoap.EventsNamespace] == "" {
		return ErrNoEvents
	}
	lenses := readLenses(setup, client, paths[onvifsoap.MediaNamespace])
	terminate := "PT" + strconv.Itoa(int(t.termination/time.Second)) + "S"
	var created struct {
		SubscriptionReference struct {
			Address             string
			ReferenceParameters struct {
				Parameters []struct {
					XMLName xml.Name
					Value   string `xml:",chardata"`
				} `xml:",any"`
			}
		}
	}
	if err := client.Do(setup, onvifsoap.Request{Address: paths[onvifsoap.EventsNamespace], Namespace: onvifsoap.EventsNamespace, Operation: "CreatePullPointSubscription",
		Action:  onvifsoap.EventsNamespace + "/EventPortType/CreatePullPointSubscriptionRequest",
		Content: "<t:InitialTerminationTime>" + terminate + "</t:InitialTerminationTime>"}, &created); err != nil {
		return err
	}
	subscription := undoublePort(strings.TrimSpace(created.SubscriptionReference.Address))
	if _, err := client.Resolve(subscription); err != nil {
		return err
	}
	// Axis returns a shared address plus reference parameters that every
	// subscription call must echo as WS-Addressing headers.
	headers := ""
	for i, parameter := range created.SubscriptionReference.ReferenceParameters.Parameters {
		if i == 4 || !itemName.MatchString(parameter.XMLName.Local) || len(parameter.XMLName.Space) > 256 || len(parameter.Value) > 256 {
			break
		}
		prefix := "rp" + strconv.Itoa(i)
		headers += "<" + prefix + ":" + parameter.XMLName.Local + ` xmlns:` + prefix + `="` + onvifsoap.Text(parameter.XMLName.Space) + `" wsa:IsReferenceParameter="true">` +
			onvifsoap.Text(strings.TrimSpace(parameter.Value)) + "</" + prefix + ":" + parameter.XMLName.Local + ">"
	}
	subscriptionCall := func(ctx context.Context, namespace, operation, action, content string, out any) error {
		return client.Do(ctx, onvifsoap.Request{Address: subscription, Namespace: namespace, Operation: operation, Action: action, Content: content, Addressing: true, Headers: headers}, out)
	}
	defer func() {
		// Release the camera's subscription slot even when ctx has ended.
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = subscriptionCall(cleanup, onvifsoap.NotifyNamespace, "Unsubscribe", "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest", "", nil)
	}()
	// Ask for the current states as Initialized messages; optional on many cameras.
	_ = subscriptionCall(setup, onvifsoap.EventsNamespace, "SetSynchronizationPoint", onvifsoap.EventsNamespace+"/PullPointSubscription/SetSynchronizationPointRequest", "", nil)
	cancel()
	if err := sink.Write(device.ID, protocol, "subscription", map[string]any{"lenses": len(lenses.sources), "reference_parameters": headers != ""}); err != nil {
		return err
	}
	tracker := states{}
	renewed, renewable := time.Now(), true
	failures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if renewable && time.Since(renewed) >= t.renew {
			call, done := context.WithTimeout(ctx, t.request)
			err := subscriptionCall(call, onvifsoap.NotifyNamespace, "Renew", "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest", "<t:TerminationTime>"+terminate+"</t:TerminationTime>", nil)
			done()
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case errors.Is(err, onvifsoap.ErrRefused):
				// Renew is optional for pull points; each pull keeps the
				// subscription alive, so stop renewing instead of reconnecting.
				renewable = false
			case err != nil:
				return err
			}
			renewed = time.Now()
			if err := sink.Write(device.ID, protocol, "heartbeat", map[string]any{"renewed": renewable}); err != nil {
				return err
			}
		}
		var pulled struct {
			NotificationMessage []notification
		}
		started := time.Now()
		call, done := context.WithTimeout(ctx, t.pull+t.request)
		err := subscriptionCall(call, onvifsoap.EventsNamespace, "PullMessages", onvifsoap.EventsNamespace+"/PullPointSubscription/PullMessagesRequest",
			"<t:Timeout>PT"+strconv.Itoa(int(t.pull/time.Second))+"S</t:Timeout><t:MessageLimit>32</t:MessageLimit>", &pulled)
		done()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, onvifsoap.ErrAuthentication) {
				return err
			}
			failures++
			if failures >= t.failures {
				return err
			}
			if pause(ctx, t.idle) != nil {
				return ctx.Err()
			}
			continue
		}
		failures = 0
		now := time.Now()
		for _, message := range pulled.NotificationMessage {
			if err := handle(device.ID, sink, message, lenses, tracker, now); err != nil {
				return err
			}
		}
		for _, stale := range tracker.expire(now, t.stale) {
			if err := sink.Write(device.ID, protocol, "event", stale); err != nil {
				return err
			}
		}
		// Some cameras answer an empty pull at once instead of waiting.
		if len(pulled.NotificationMessage) == 0 && time.Since(started) < t.idle {
			if pause(ctx, t.idle-time.Since(started)) != nil {
				return ctx.Err()
			}
		}
	}
}

func pause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var doubledPort = regexp.MustCompile(`^(http://[^/:]+:\d+):\d+(/.*)?$`)

// undoublePort repairs subscription addresses such as host:8106:8106 that
// some cameras return.
func undoublePort(address string) string {
	return doubledPort.ReplaceAllString(address, "$1$2")
}

// handle journals one notification and emits the brand-neutral transitions.
func handle(deviceID string, sink capture.Sink, message notification, lenses lenses, tracker states, now time.Time) error {
	topic := stripTopic(message.Topic)
	inner := message.Message.Message
	source, data := inner.Source.values(), inner.Data.values()
	operation := inner.PropertyOperation
	if err := sink.Write(deviceID, protocol, "notification", map[string]any{"topic": clean(topic), "operation": clean(operation),
		"utc": clean(inner.UtcTime), "source": source, "data": data}); err != nil {
		return err
	}
	matched, ok := findRule(topic)
	if !ok {
		return nil
	}
	index := lenses.index(source, matched.bySource)
	ruleID := source["Rule"]
	provenanceTopic := topic
	if matched.bySource != "" {
		// Foscam publishes several independent alarm states under one topic;
		// its source alarm name must survive both tracking and normalization.
		provenanceTopic += ":" + source[matched.bySource]
	}
	provenance := protocol + ":" + provenanceTopic
	base := provenanceTopic + "\x00" + strconv.Itoa(index) + "\x00" + ruleID + "\x00" + source["VideoSourceConfigurationToken"]
	emit := func(code, action string, classes []string) error {
		return sink.Write(deviceID, protocol, "event", cameraevents.Canonical(code, action, index, provenance, classes, ruleID))
	}
	// transition opens or closes the intervals of one detection key.
	transition := func(key string, active bool, wanted []interval) error {
		if operation == "Deleted" {
			active = false
		}
		if !active {
			// End every interval the start opened; an end may omit the class.
			for _, open := range tracker.close(key) {
				if err := emit(open.code, "Stop", open.classes); err != nil {
					return err
				}
			}
			return nil
		}
		if matched.classState {
			// ObjectDetection reports the current class set. End classes that
			// disappeared even when another class keeps the detection active.
			for _, removed := range tracker.retain(key, wanted) {
				if err := emit(removed.code, "Stop", removed.classes); err != nil {
					return err
				}
			}
		}
		for _, open := range wanted {
			if open.code != "" && tracker.open(key, open, now) {
				if err := emit(open.code, "Start", open.classes); err != nil {
					return err
				}
			}
		}
		return nil
	}
	switch {
	case matched.byItem:
		for name, code := range itemCodes {
			value, present := item(data, name)
			active, known := boolValue(value)
			if operation == "Deleted" || (present && known) {
				if err := transition(base+"\x00"+name, active, []interval{{code: code}}); err != nil {
					return err
				}
			}
		}
		return nil
	case matched.classState:
		found := classes(data)
		var wanted []interval
		for _, class := range found {
			wanted = append(wanted, interval{code: classCodes[class]})
		}
		return transition(base, len(found) > 0, wanted)
	case matched.state == nil:
		if operation == "Initialized" {
			return nil
		}
		return emit(matched.code, "Pulse", classes(data))
	}
	active, known := false, false
	for _, name := range matched.state {
		value, present := item(data, name)
		if active, known = boolValue(value); present && known {
			break
		}
	}
	if operation == "Deleted" {
		active, known = false, true
	}
	if !known {
		return nil
	}
	code := matched.code
	if matched.bySource != "" {
		if class := sourceClass(source[matched.bySource]); class != "" {
			code = classCodes[class]
		}
	}
	if matched.trueOnly {
		if !active || operation == "Initialized" {
			return nil
		}
		return emit(code, "Pulse", nil)
	}
	wanted := []interval{{code: code, classes: classes(data)}}
	if matched.byClass {
		wanted = nil
		for _, class := range classes(data) {
			wanted = append(wanted, interval{code: classCodes[class]})
		}
	}
	return transition(base, active, wanted)
}

type interval struct {
	code    string
	classes []string
}

type detection struct {
	intervals []interval
	updated   time.Time
}

// states remembers the intervals open per detection so only transitions are
// emitted, an end closes everything its start opened, and an interval whose
// end never arrives is closed after a bound.
type states map[string]*detection

func (s states) open(key string, wanted interval, now time.Time) bool {
	tracked := s[key]
	if tracked == nil {
		if len(s) >= 256 {
			return false
		}
		tracked = &detection{}
		s[key] = tracked
	}
	tracked.updated = now
	for _, existing := range tracked.intervals {
		if existing.code == wanted.code {
			return false
		}
	}
	tracked.intervals = append(tracked.intervals, wanted)
	return true
}

func (s states) close(key string) []interval {
	tracked := s[key]
	delete(s, key)
	if tracked == nil {
		return nil
	}
	return tracked.intervals
}

// retain removes classes absent from a complete class-state snapshot.
func (s states) retain(key string, wanted []interval) []interval {
	tracked := s[key]
	if tracked == nil {
		return nil
	}
	var kept, removed []interval
	for _, existing := range tracked.intervals {
		found := false
		for _, next := range wanted {
			if existing.code == next.code {
				found = true
				break
			}
		}
		if found {
			kept = append(kept, existing)
		} else {
			removed = append(removed, existing)
		}
	}
	tracked.intervals = kept
	return removed
}

// expire closes detections not refreshed within limit; the returned events
// carry no lens context beyond what the start had, so they are rebuilt here.
func (s states) expire(now time.Time, limit time.Duration) []map[string]any {
	var keys []string
	for key, tracked := range s {
		if now.Sub(tracked.updated) >= limit {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var result []map[string]any
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 5)
		index, _ := strconv.Atoi(parts[1])
		for _, open := range s.close(key) {
			result = append(result, cameraevents.Canonical(open.code, "Stop", index, protocol+":"+parts[0], open.classes, parts[2]))
		}
	}
	return result
}

type lenses struct {
	sources []string
	configs map[string]string
}

// readLenses maps video source and source configuration tokens to lens
// indexes in the camera's own order. Failure leaves the inventory unknown.
func readLenses(ctx context.Context, client *onvifsoap.Client, mediaPath string) lenses {
	result := lenses{configs: map[string]string{}}
	if mediaPath == "" {
		return result
	}
	var sources struct {
		VideoSources []struct {
			Token string `xml:"token,attr"`
		}
	}
	if client.Call(ctx, mediaPath, onvifsoap.MediaNamespace, "GetVideoSources", "", &sources) == nil {
		if len(sources.VideoSources) <= 64 {
			seen := map[string]bool{}
			for _, source := range sources.VideoSources {
				if !itemName.MatchString(source.Token) || seen[source.Token] {
					// A filtered inventory is not proof of a single lens, and
					// would shift every later source's advertised index.
					result.sources = nil
					break
				}
				seen[source.Token] = true
				result.sources = append(result.sources, source.Token)
			}
		}
	}
	var configurations struct {
		Configurations []struct {
			Token       string `xml:"token,attr"`
			SourceToken string
		}
	}
	if client.Call(ctx, mediaPath, onvifsoap.MediaNamespace, "GetVideoSourceConfigurations", "", &configurations) == nil {
		for _, configuration := range configurations.Configurations {
			if itemName.MatchString(configuration.Token) && len(result.configs) < 64 {
				result.configs[configuration.Token] = configuration.SourceToken
			}
		}
	}
	return result
}

// index resolves explicit source tokens against the discovered inventory.
// Only a known single-lens device may omit them; unknown or conflicting tokens
// and unknown inventories stay unrouted. alarmItem names a vendor field whose
// documented value is an alarm discriminator rather than a video source token.
func (l lenses) index(source map[string]string, alarmItem string) int {
	if len(l.sources) == 0 {
		return -1
	}
	find := func(token string) int {
		for i, candidate := range l.sources {
			if token != "" && candidate == token {
				return i
			}
		}
		return -1
	}
	index := -1
	accept := func(token string) bool {
		resolved := find(token)
		if resolved < 0 || (index >= 0 && index != resolved) {
			return false
		}
		index = resolved
		return true
	}
	for _, name := range []string{"VideoSourceToken", "VideoSource", "Source", "InputToken"} {
		if name == alarmItem {
			continue
		}
		if token, present := source[name]; present && !accept(token) {
			return -1
		}
	}
	for _, name := range []string{"VideoSourceConfigurationToken", "VideoSourceConfiguration"} {
		if token, present := source[name]; present && !accept(l.configs[token]) {
			return -1
		}
	}
	if index < 0 && len(l.sources) == 1 {
		return 0
	}
	return index
}

func clean(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
}
