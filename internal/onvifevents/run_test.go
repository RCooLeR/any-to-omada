package onvifevents

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/onvifsoap"
)

type write struct {
	protocol, kind string
	data           any
}

type sink struct {
	mu     sync.Mutex
	writes []write
}

func (s *sink) Write(_, protocol, kind string, data any) error {
	s.mu.Lock()
	s.writes = append(s.writes, write{protocol, kind, data})
	s.mu.Unlock()
	return nil
}

func (s *sink) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []map[string]any
	for _, w := range s.writes {
		if w.kind == "event" {
			result = append(result, w.data.(map[string]any))
		}
	}
	return result
}

func (s *sink) count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, w := range s.writes {
		if w.kind == kind {
			n++
		}
	}
	return n
}

type camera struct {
	t           *testing.T
	server      *httptest.Server
	mu          sync.Mutex
	batches     [][]string
	operations  []string
	addressedTo []string
	lenses      int
	otherHost   bool
	reject      bool
	quirks      bool
	noInventory bool
	bodies      []string
}

var operation = regexp.MustCompile(`<s:Body><t:([A-Za-z]+)[ >/]`)
var to = regexp.MustCompile(`<wsa:To>([^<]*)</wsa:To>`)

func newCamera(t *testing.T) *camera {
	c := &camera{t: t, lenses: 1}
	c.server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

func message(topic, operation string, source, data map[string]string) string {
	items := func(values map[string]string) string {
		result := ""
		for name, value := range values {
			result += `<tt:SimpleItem Name="` + name + `" Value="` + value + `"/>`
		}
		return result
	}
	return `<wsnt:NotificationMessage><wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">` + topic + `</wsnt:Topic>` +
		`<wsnt:Message><tt:Message UtcTime="2026-10-17T08:00:00Z" PropertyOperation="` + operation + `"><tt:Source>` + items(source) + `</tt:Source>` +
		`<tt:Data>` + items(data) + `</tt:Data></tt:Message></wsnt:Message></wsnt:NotificationMessage>`
}

func (c *camera) queue(messages ...string) {
	c.mu.Lock()
	c.batches = append(c.batches, messages)
	c.mu.Unlock()
}

func (c *camera) seen(op string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, candidate := range c.operations {
		if candidate == op {
			n++
		}
	}
	return n
}

func (c *camera) serve(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	match := operation.FindStringSubmatch(body)
	if match == nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	op := match[1]
	c.mu.Lock()
	c.operations = append(c.operations, op)
	c.bodies = append(c.bodies, op+" "+body)
	if address := to.FindStringSubmatch(body); address != nil {
		c.addressedTo = append(c.addressedTo, op+" "+address[1])
	}
	c.mu.Unlock()
	if op != "GetSystemDateAndTime" && c.reject {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	reply := func(namespace, content string) {
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:x="%s" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:dom0="http://www.axis.com/2009/event"><s:Body><x:%sResponse>%s</x:%sResponse></s:Body></s:Envelope>`, namespace, op, content, op)
	}
	base := "http://" + r.Host
	switch op {
	case "GetSystemDateAndTime":
		reply(onvifsoap.DeviceNamespace, "")
	case "GetDeviceInformation":
		reply(onvifsoap.DeviceNamespace, `<x:Manufacturer>Reolink</x:Manufacturer><x:Model>RLC-810A</x:Model><x:FirmwareVersion>v3.1.0</x:FirmwareVersion><x:SerialNumber>private-serial</x:SerialNumber>`)
	case "GetServices":
		reply(onvifsoap.DeviceNamespace, `<x:Service><x:Namespace>`+onvifsoap.EventsNamespace+`</x:Namespace><x:XAddr>`+base+`/onvif/event_service</x:XAddr></x:Service>`+
			`<x:Service><x:Namespace>`+onvifsoap.MediaNamespace+`</x:Namespace><x:XAddr>`+base+`/onvif/media_service</x:XAddr></x:Service>`)
	case "GetVideoSources":
		if c.noInventory {
			http.Error(w, "source inventory unavailable", http.StatusInternalServerError)
			return
		}
		content := ""
		for i := 0; i < c.lenses; i++ {
			content += `<x:VideoSources token="VideoSource_` + strconv.Itoa(i) + `"/>`
		}
		reply(onvifsoap.MediaNamespace, content)
	case "GetVideoSourceConfigurations":
		content := ""
		for i := 0; i < c.lenses; i++ {
			content += `<x:Configurations token="VSC_` + strconv.Itoa(i) + `"><tt:SourceToken>VideoSource_` + strconv.Itoa(i) + `</tt:SourceToken></x:Configurations>`
		}
		reply(onvifsoap.MediaNamespace, content)
	case "CreatePullPointSubscription":
		address := base + "/onvif/subscription?Idx=7"
		if c.otherHost {
			address = "http://192.0.2.10/onvif/subscription?Idx=7"
		}
		parameters := ""
		if c.quirks {
			_, port, _ := net.SplitHostPort(r.Host)
			address = base + ":" + port + "/onvif/subscription?Idx=7"
			parameters = `<wsa:ReferenceParameters><dom0:SubscriptionId>42</dom0:SubscriptionId></wsa:ReferenceParameters>`
		}
		reply(onvifsoap.EventsNamespace, `<x:SubscriptionReference><wsa:Address>`+address+`</wsa:Address>`+parameters+`</x:SubscriptionReference>`)
	case "PullMessages":
		c.mu.Lock()
		var batch []string
		if len(c.batches) > 0 {
			batch, c.batches = c.batches[0], c.batches[1:]
		}
		c.mu.Unlock()
		if batch == nil {
			time.Sleep(20 * time.Millisecond)
		}
		reply(onvifsoap.EventsNamespace, "<x:CurrentTime>2026-10-17T08:00:00Z</x:CurrentTime>"+strings.Join(batch, ""))
	case "Renew":
		if c.quirks {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code></s:Fault></s:Body></s:Envelope>`)
			return
		}
		reply(onvifsoap.NotifyNamespace, "")
	case "Unsubscribe":
		reply(onvifsoap.NotifyNamespace, "")
	case "SetSynchronizationPoint":
		reply(onvifsoap.EventsNamespace, "")
	default:
		http.Error(w, "bad", http.StatusBadRequest)
	}
}

func (c *camera) device() capture.Device {
	host, port, _ := net.SplitHostPort(c.server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	return capture.Device{ID: "cam", Host: host, NativePort: number, Username: "admin", Password: "secret"}
}

var testTimings = timings{pull: time.Second, termination: time.Minute, renew: 200 * time.Millisecond, request: time.Second, idle: 10 * time.Millisecond, stale: time.Minute, failures: 2}

func runFor(t *testing.T, c *camera, until func(*sink) bool) (*sink, error) {
	t.Helper()
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, c.device(), s, testTimings) }()
	deadline := time.Now().Add(5 * time.Second)
	for !until(s) && time.Now().Before(deadline) {
		select {
		case err := <-done:
			cancel()
			return s, err
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	return s, <-done
}

func summary(event map[string]any) string {
	data, _ := event["Data"].(map[string]any)
	return fmt.Sprintf("%s %s %v %v %v", event["Code"], event["Action"], event["Index"], data["ObjectTypes"], data["RuleID"])
}

func TestPullPointTurnsTopicsIntoTransitions(t *testing.T) {
	c := newCamera(t)
	c.queue(
		message("tns1:RuleEngine/CellMotionDetector/Motion", "Initialized", map[string]string{"VideoSourceConfigurationToken": "VSC_0", "Rule": "MyMotionDetectorRule"}, map[string]string{"IsMotion": "false"}),
		message("tns1:RuleEngine/CellMotionDetector/Motion", "Changed", map[string]string{"VideoSourceConfigurationToken": "VSC_0", "Rule": "MyMotionDetectorRule"}, map[string]string{"IsMotion": "true"}),
		message("tns1:RuleEngine/CellMotionDetector/Motion", "Changed", map[string]string{"VideoSourceConfigurationToken": "VSC_0", "Rule": "MyMotionDetectorRule"}, map[string]string{"IsMotion": "true"}),
		message("tns1:RuleEngine/MyRuleDetector/PeopleDetect", "Changed", map[string]string{"Source": "VideoSource_0"}, map[string]string{"State": "true"}),
		message("tns1:RuleEngine/LineDetector/Crossed", "Changed", map[string]string{"Rule": "Line1"}, map[string]string{"ObjectId": "4"}),
		message("tns1:RuleEngine/ObjectDetector/Object", "Changed", nil, map[string]string{"ObjectType": "Vehicle", "State": "true"}),
		message("tnsvendor:Unknown/Topic", "Changed", nil, map[string]string{"State": "true"}),
	)
	c.queue(
		message("tns1:RuleEngine/CellMotionDetector/Motion", "Changed", map[string]string{"VideoSourceConfigurationToken": "VSC_0", "Rule": "MyMotionDetectorRule"}, map[string]string{"IsMotion": "false"}),
		message("tns1:RuleEngine/MyRuleDetector/PeopleDetect", "Deleted", map[string]string{"Source": "VideoSource_0"}, nil),
	)
	s, err := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 6 && s.count("heartbeat") > 0 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	var got []string
	for _, event := range s.events() {
		got = append(got, summary(event))
	}
	want := []string{
		"VideoMotion Start 0 <nil> MyMotionDetectorRule",
		"SmartMotionHuman Start 0 <nil> <nil>",
		"CrossLineDetection Pulse 0 <nil> Line1",
		"SmartMotionVehicle Start 0 <nil> <nil>",
		"VideoMotion Stop 0 <nil> MyMotionDetectorRule",
		"SmartMotionHuman Stop 0 <nil> <nil>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
	if s.count("notification") != 9 || c.seen("Renew") == 0 || c.seen("Unsubscribe") != 1 {
		t.Fatalf("notifications %d renew %d unsubscribe %d", s.count("notification"), c.seen("Renew"), c.seen("Unsubscribe"))
	}
	for _, w := range s.writes {
		if strings.Contains(fmt.Sprint(w.data), "private-serial") || strings.Contains(fmt.Sprint(w.data), "secret") {
			t.Fatal("identity or credentials leaked into the journal")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, addressed := range c.addressedTo {
		if !strings.HasSuffix(addressed, "/onvif/subscription?Idx=7") {
			t.Fatalf("subscription call addressed to %s", addressed)
		}
	}
	if len(c.addressedTo) == 0 {
		t.Fatal("subscription calls lack WS-Addressing To")
	}
}

func TestAxisAndReolinkVendorTopics(t *testing.T) {
	c := newCamera(t)
	c.queue(
		message("tnsaxis:CameraApplicationPlatform/VMD/Camera1ProfileANY", "Initialized", map[string]string{}, map[string]string{"active": "0"}),
		message("tnsaxis:CameraApplicationPlatform/VMD/Camera1ProfileANY", "Changed", map[string]string{}, map[string]string{"active": "1"}),
		message("tnsaxis:CameraApplicationPlatform/ObjectAnalytics/Device1Scenario1", "Changed", nil, map[string]string{"active": "1", "classTypes": "human", "objectId": "12"}),
		message("tns1:VideoSource/tnsaxis:Tampering", "Changed", map[string]string{"channel": "1"}, map[string]string{"tampering": "1"}),
		message("tns1:RuleEngine/PeopleDetect", "Changed", nil, map[string]string{"State": "true"}),
	)
	c.queue(
		message("tnsaxis:CameraApplicationPlatform/ObjectAnalytics/Device1Scenario1", "Changed", nil, map[string]string{"active": "0"}),
		message("tnsaxis:CameraApplicationPlatform/VMD/Camera1ProfileANY", "Changed", map[string]string{}, map[string]string{"active": "0"}),
	)
	s, _ := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 6 })
	var got []string
	for _, event := range s.events() {
		got = append(got, summary(event))
	}
	want := []string{
		"VideoMotion Start 0 <nil> <nil>",
		"SmartMotionHuman Start 0 <nil> <nil>",
		"VideoBlind Pulse 0 <nil> <nil>",
		"SmartMotionHuman Start 0 <nil> <nil>",
		"SmartMotionHuman Stop 0 <nil> <nil>",
		"VideoMotion Stop 0 <nil> <nil>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
}

func TestMultiLensEventsUseTheVideoSourceOrder(t *testing.T) {
	c := newCamera(t)
	c.lenses = 2
	c.queue(
		message("tns1:VideoSource/MotionAlarm", "Changed", map[string]string{"Source": "VideoSource_1"}, map[string]string{"State": "true"}),
		message("tns1:VideoSource/MotionAlarm", "Changed", map[string]string{"Source": "VideoSource_9"}, map[string]string{"State": "true"}),
	)
	s, _ := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 2 })
	events := s.events()
	if len(events) != 2 || events[0]["Index"] != 1 {
		t.Fatalf("events = %v", events)
	}
	if _, present := events[1]["Index"]; present {
		t.Fatal("an unknown lens token was routed")
	}
}

func TestSubscriptionOnAnotherHostIsRefused(t *testing.T) {
	c := newCamera(t)
	c.otherHost = true
	if _, err := runFor(t, c, func(*sink) bool { return false }); !errors.Is(err, onvifsoap.ErrUnavailable) || c.seen("PullMessages") != 0 {
		t.Fatalf("err = %v, pulls %d", err, c.seen("PullMessages"))
	}
}

func TestRejectedCredentialsStopTheSource(t *testing.T) {
	c := newCamera(t)
	c.reject = true
	if _, err := runFor(t, c, func(*sink) bool { return false }); !errors.Is(err, capture.ErrAuthentication) {
		t.Fatalf("err = %v", err)
	}
}

func TestTopicHelpers(t *testing.T) {
	if stripTopic("tns1:RuleEngine/tnsaxis:VMD/Camera1") != "RuleEngine/VMD/Camera1" {
		t.Fatal("prefixes kept")
	}
	if got := classes(map[string]string{"ObjectType": "Human", "ClassTypes": "Vehicle Animal"}); strings.Join(got, ",") != "human,vehicle,pet" {
		t.Fatalf("classes = %v", got)
	}
	if _, ok := boolValue("maybe"); ok {
		t.Fatal("unknown boolean accepted")
	}
}

func TestSubscriptionQuirksAreHandled(t *testing.T) {
	c := newCamera(t)
	c.quirks = true
	c.queue(message("tns1:RuleEngine/CellMotionDetector/Motion", "Changed", nil, map[string]string{"IsMotion": "true"}))
	s, err := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 1 && c.seen("Renew") >= 1 && c.seen("PullMessages") >= 3 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a refused Renew ended the subscription: %v", err)
	}
	if c.seen("SetSynchronizationPoint") != 1 || c.seen("Renew") != 1 {
		t.Fatalf("sync %d renew %d", c.seen("SetSynchronizationPoint"), c.seen("Renew"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	echoed := 0
	for _, body := range c.bodies {
		if strings.HasPrefix(body, "PullMessages ") {
			if !strings.Contains(body, `<rp0:SubscriptionId xmlns:rp0="http://www.axis.com/2009/event" wsa:IsReferenceParameter="true">42</rp0:SubscriptionId>`) {
				t.Fatalf("reference parameter not echoed: %s", body)
			}
			echoed++
		}
	}
	for _, addressed := range c.addressedTo {
		if strings.Count(addressed, ":") > 2 {
			t.Fatalf("doubled port kept: %s", addressed)
		}
	}
	if echoed == 0 || len(s.events()) != 1 {
		t.Fatal("no pull carried the reference parameter")
	}
}

func TestVendorItemClassAndPulseRules(t *testing.T) {
	c := newCamera(t)
	c.queue(
		message("tns1:RuleEngine/TPSmartEventDetector/TPSmartEvent", "Changed", nil, map[string]string{"IsVehicle": "true"}),
		message("tns1:RuleEngine/PeopleDetector/People", "Changed", nil, map[string]string{"IsPeople": "true"}),
		message("tns1:RuleEngine/ObjectDetection/Object", "Changed", nil, map[string]string{"ClassTypes": "Human Vehical"}),
		message("tns1:UserAlarm/IVA/HumanShapeDetect", "Changed", nil, map[string]string{"State": "true"}),
		message("tns1:Device/Trigger/MotionDetector", "Changed", map[string]string{"VideoSource": "HUMAN_DETECTION_ALARM"}, map[string]string{"State": "true"}),
		message("tns1:VideoAnalytics/Motion", "Changed", nil, map[string]string{"Level": "Trigger"}),
	)
	c.queue(
		message("tns1:RuleEngine/TPSmartEventDetector/TPSmartEvent", "Changed", nil, map[string]string{"IsVehicle": "false"}),
		message("tns1:RuleEngine/ObjectDetection/Object", "Changed", nil, map[string]string{"ClassTypes": ""}),
		message("tns1:VideoAnalytics/Motion", "Changed", nil, map[string]string{"Level": "Normal"}),
	)
	s, _ := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 11 })
	var got []string
	for _, event := range s.events() {
		got = append(got, fmt.Sprint(event["Code"], " ", event["Action"]))
	}
	want := []string{
		"SmartMotionVehicle Start", "SmartMotionHuman Start", "SmartMotionHuman Start", "SmartMotionVehicle Start",
		"SmartMotionHuman Pulse", "SmartMotionHuman Start", "VideoMotion Start",
		"SmartMotionVehicle Stop", "SmartMotionHuman Stop", "SmartMotionVehicle Stop", "VideoMotion Stop",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
}

func TestStaleIntervalsAndEmptyPullsAreBounded(t *testing.T) {
	c := newCamera(t)
	c.queue(message("tns1:RuleEngine/FieldDetector/ObjectsInside", "Changed", nil, map[string]string{"IsInside": "true"}))
	s := &sink{}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	timing := testTimings
	timing.idle, timing.stale = 300*time.Millisecond, 400*time.Millisecond
	_ = run(ctx, c.device(), s, timing)
	var got []string
	for _, event := range s.events() {
		got = append(got, fmt.Sprint(event["Code"], " ", event["Action"]))
	}
	if strings.Join(got, ",") != "CrossRegionDetection Start,CrossRegionDetection Stop" {
		t.Fatalf("events = %v", got)
	}
	if pulls := c.seen("PullMessages"); pulls > 6 {
		t.Fatalf("empty pulls were not throttled: %d", pulls)
	}
}

func applyMessage(t *testing.T, s *sink, tracker states, topic, operation string, source, data map[string]string, now time.Time) {
	t.Helper()
	var notification notification
	if err := xml.Unmarshal([]byte(message(topic, operation, source, data)), &notification); err != nil {
		t.Fatal(err)
	}
	if err := handle("cam", s, notification, lenses{sources: []string{"VideoSource_0"}}, tracker, now); err != nil {
		t.Fatal(err)
	}
}

func TestDeletedItemStateClosesWithoutData(t *testing.T) {
	s, tracker := &sink{}, states{}
	now := time.Now()
	topic := "tns1:RuleEngine/PeopleDetector/People"
	applyMessage(t, s, tracker, topic, "Changed", nil, map[string]string{"IsPeople": "true"}, now)
	applyMessage(t, s, tracker, topic, "Deleted", nil, nil, now.Add(time.Second))
	events := s.events()
	if len(events) != 2 || summary(events[0]) != "SmartMotionHuman Start 0 <nil> <nil>" || summary(events[1]) != "SmartMotionHuman Stop 0 <nil> <nil>" || len(tracker) != 0 {
		t.Fatalf("deleted notification did not close its property: %v, open=%d", events, len(tracker))
	}
}

func TestSourceAlarmStatesStayIndependentThroughExpiry(t *testing.T) {
	s, tracker := &sink{}, states{}
	now := time.Now()
	topic := "tns1:Device/Trigger/MotionDetector"
	human := map[string]string{"VideoSource": "HUMAN_DETECTION_ALARM"}
	motion := map[string]string{"VideoSource": "MOTION_DETECTION_ALARM"}
	applyMessage(t, s, tracker, topic, "Changed", human, map[string]string{"State": "true"}, now)
	applyMessage(t, s, tracker, topic, "Changed", motion, map[string]string{"State": "true"}, now)
	applyMessage(t, s, tracker, topic, "Changed", motion, map[string]string{"State": "false"}, now.Add(time.Second))
	events := s.events()
	if len(events) != 3 || summary(events[2]) != "VideoMotion Stop 0 <nil> <nil>" || len(tracker) != 1 {
		t.Fatalf("motion stop affected another source alarm: %v, open=%d", events, len(tracker))
	}
	stale := tracker.expire(now.Add(time.Minute), time.Minute)
	if len(stale) != 1 || summary(stale[0]) != "SmartMotionHuman Stop 0 <nil> <nil>" {
		t.Fatalf("remaining human alarm was lost: %v", stale)
	}
	startData := events[0]["Data"].(map[string]any)
	stopData := stale[0]["Data"].(map[string]any)
	if startData["event"] != stopData["event"] || startData["event"] == events[1]["Data"].(map[string]any)["event"] {
		t.Fatal("canonical provenance lost the source alarm discriminator")
	}
}

func TestClassStateReplacesRemovedClasses(t *testing.T) {
	s, tracker := &sink{}, states{}
	now := time.Now()
	topic := "tns1:RuleEngine/ObjectDetection/Object"
	for i, classSet := range []string{"Human Vehicle", "Vehicle", "Pet", ""} {
		applyMessage(t, s, tracker, topic, "Changed", nil, map[string]string{"ClassTypes": classSet}, now.Add(time.Duration(i)*time.Second))
	}
	var got []string
	for _, event := range s.events() {
		got = append(got, fmt.Sprint(event["Code"], " ", event["Action"]))
	}
	want := "SmartMotionHuman Start,SmartMotionVehicle Start,SmartMotionHuman Stop,SmartMotionVehicle Stop,SmartMotionPet Start,SmartMotionPet Stop"
	if strings.Join(got, ",") != want || len(tracker) != 0 {
		t.Fatalf("class snapshot transitions = %v, open=%d", got, len(tracker))
	}
}

func TestSourceAlarmClassUsesWholeTokens(t *testing.T) {
	for _, test := range []struct{ alarm, want string }{
		{"HUMAN_DETECTION_ALARM", "human"}, {"CAR_DETECTION_ALARM", "vehicle"}, {"ANIMAL_DETECTION_ALARM", "pet"},
		{"CARD_ACCESS_ALARM", ""}, {"CARPET_ALARM", ""}, {"INHUMAN_ALARM", ""},
	} {
		if got := sourceClass(test.alarm); got != test.want {
			t.Errorf("sourceClass(%q) = %q, want %q", test.alarm, got, test.want)
		}
	}
}

func TestLensIndexRequiresKnownInventoryAndConsistentTokens(t *testing.T) {
	single := lenses{sources: []string{"VideoSource_0"}, configs: map[string]string{"VSC_0": "VideoSource_0"}}
	multiple := lenses{sources: []string{"VideoSource_0", "VideoSource_1"}, configs: map[string]string{"VSC_0": "VideoSource_0", "VSC_1": "VideoSource_1"}}
	for _, test := range []struct {
		name      string
		inventory lenses
		source    map[string]string
		alarmItem string
		want      int
	}{
		{"unknown inventory without token", lenses{}, nil, "", -1},
		{"unknown inventory with token", lenses{}, map[string]string{"VideoSourceToken": "VideoSource_0"}, "", -1},
		{"known single without token", single, nil, "", 0},
		{"known single matching token", single, map[string]string{"VideoSourceToken": "VideoSource_0"}, "", 0},
		{"known single unknown token", single, map[string]string{"VideoSourceToken": "VideoSource_9"}, "", -1},
		{"known single empty token", single, map[string]string{"VideoSourceToken": ""}, "", -1},
		{"known single matching configuration", single, map[string]string{"VideoSourceConfigurationToken": "VSC_0"}, "", 0},
		{"known single unknown configuration", single, map[string]string{"VideoSourceConfigurationToken": "VSC_9"}, "", -1},
		{"unknown configuration despite known source", single, map[string]string{"VideoSourceToken": "VideoSource_0", "VideoSourceConfigurationToken": "VSC_9"}, "", -1},
		{"known multiple without token", multiple, nil, "", -1},
		{"known multiple matching configuration", multiple, map[string]string{"VideoSourceConfigurationToken": "VSC_1"}, "", 1},
		{"known multiple conflicting tokens", multiple, map[string]string{"VideoSourceToken": "VideoSource_0", "VideoSourceConfigurationToken": "VSC_1"}, "", -1},
		{"alarm discriminator is not a source token", single, map[string]string{"VideoSource": "HUMAN_DETECTION_ALARM"}, "VideoSource", 0},
		{"alarm discriminator cannot hide unknown source", single, map[string]string{"VideoSource": "HUMAN_DETECTION_ALARM", "VideoSourceToken": "VideoSource_9"}, "VideoSource", -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.inventory.index(test.source, test.alarmItem); got != test.want {
				t.Fatalf("lens index = %d, want %d", got, test.want)
			}
		})
	}
}

func TestUnknownSourceInventoryDoesNotRouteMotionToFirstLens(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovery_failed=%t", failed), func(t *testing.T) {
			c := newCamera(t)
			c.lenses, c.noInventory = 0, failed
			c.queue(message("tns1:RuleEngine/CellMotionDetector/Motion", "Changed", nil, map[string]string{"IsMotion": "true"}))
			s, _ := runFor(t, c, func(s *sink) bool { return len(s.events()) >= 1 })
			events := s.events()
			if len(events) != 1 {
				t.Fatalf("events = %v", events)
			}
			if _, routed := events[0]["Index"]; routed {
				t.Fatal("an unknown camera inventory was routed to lens zero")
			}
		})
	}
}
