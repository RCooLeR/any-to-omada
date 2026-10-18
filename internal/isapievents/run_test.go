package isapievents

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
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

func (s *sink) events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []string
	for _, w := range s.writes {
		if w.kind != "event" {
			continue
		}
		event := w.data.(map[string]any)
		data := event["Data"].(map[string]any)
		result = append(result, fmt.Sprintf("%s %s %v %v %v %v", event["Code"], event["Action"], event["Index"], data["event"], data["ObjectTypes"], data["RuleID"]))
	}
	return result
}

func (s *sink) has(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.writes {
		if w.kind == kind {
			return true
		}
	}
	return false
}

func xmlAlert(eventType, state, channel, extra string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><EventNotificationAlert version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">` +
		`<ipAddress>192.0.2.64</ipAddress><portNo>80</portNo><protocol>HTTP</protocol><macAddress>aa:bb:cc:dd:ee:ff</macAddress>` +
		`<channelID>` + channel + `</channelID><dateTime>2026-10-17T10:00:00+03:00</dateTime><activePostCount>1</activePostCount>` +
		`<eventType>` + eventType + `</eventType><eventState>` + state + `</eventState><eventDescription>x</eventDescription>` + extra + `</EventNotificationAlert>`
}

type hik struct {
	server     *httptest.Server
	parts      chan string
	reject     bool
	streams    int
	infoStatus int
	mu         sync.Mutex
}

func newHik(t *testing.T) *hik {
	h := &hik{parts: make(chan string, 32)}
	h.server = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.server.Close)
	return h
}

func (h *hik) authorized(r *http.Request) bool {
	fields := map[string]string{}
	for _, match := range regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^, ]+))`).FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
		fields[match[1]] = match[2] + match[3]
	}
	if strings.Contains(r.Header.Get("Authorization"), `qop="`) || strings.Contains(r.Header.Get("Authorization"), `nc="`) || strings.Contains(r.Header.Get("Authorization"), `algorithm="`) {
		return false
	}
	hash := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
	ha1, ha2 := hash("admin:hik:secret"), hash("GET:"+r.URL.Path)
	return !h.reject && fields["uri"] == r.URL.Path && fields["response"] == hash(ha1+":n1:"+fields["nc"]+":"+fields["cnonce"]+":auth:"+ha2)
}

func (h *hik) serve(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Digest realm="hik", nonce="n1", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case infoPath:
		if h.infoStatus != 0 {
			w.WriteHeader(h.infoStatus)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0"?><DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"><deviceName>yard</deviceName><serialNumber>private-serial</serialNumber><model>DS-2CD2387G2-LU</model><firmwareVersion>V5.7.3</firmwareVersion><firmwareReleasedDate>build 230101</firmwareReleasedDate></DeviceInfo>`)
	case streamPath:
		h.mu.Lock()
		h.streams++
		h.mu.Unlock()
		w.Header().Set("Content-Type", "multipart/mixed; boundary=boundary")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case part, ok := <-h.parts:
				if !ok {
					return
				}
				fmt.Fprint(w, part)
				w.(http.Flusher).Flush()
			}
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func part(contentType, body string) string {
	return "--boundary\r\nContent-Type: " + contentType + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body + "\r\n"
}

func (h *hik) device() capture.Device {
	host, port, _ := net.SplitHostPort(h.server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	return capture.Device{ID: "hik", Host: host, NativePort: number, Username: "admin", Password: "secret"}
}

var testTimings = timings{request: time.Second, idle: 2 * time.Second, quiet: 300 * time.Millisecond, heartbeat: time.Hour}

func runUntil(t *testing.T, h *hik, until func(*sink) bool) (*sink, error) {
	t.Helper()
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.device(), s, testTimings) }()
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

func TestAlertStreamFoldsRepeatedAlertsIntoIntervals(t *testing.T) {
	h := newHik(t)
	h.parts <- part("application/xml; charset=\"UTF-8\"", xmlAlert("videoloss", "inactive", "1", ""))
	for range 3 {
		h.parts <- part("application/xml", xmlAlert("VMD", "active", "1", ""))
	}
	h.parts <- part("application/xml", xmlAlert("VMD", "inactive", "1", ""))
	h.parts <- part("image/jpeg", strings.Repeat("\xff", 2048))
	h.parts <- part("application/xml", xmlAlert("linedetection", "active", "2",
		`<DetectionRegionList><DetectionRegionEntry><regionID>3</regionID><detectionTarget>human</detectionTarget></DetectionRegionEntry></DetectionRegionList>`))
	h.parts <- part("application/json", `{"ipAddress":"192.0.2.64","channelID":1,"eventType":"VMD","eventState":"active","targetType":"vehicle"}`)
	h.parts <- part("application/xml", xmlAlert("shelteralarm", "active", "1", ""))
	s, err := runUntil(t, h, func(s *sink) bool { return len(s.events()) >= 10 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	want := []string{
		"VideoMotion Start 0 isapi:VMD <nil> <nil>",
		"VideoMotion Stop 0 isapi:VMD <nil> <nil>",
		"CrossLineDetection Start 1 isapi:linedetection [human] 3",
		"VideoMotion Start 0 isapi:VMD <nil> <nil>",
		"SmartMotionVehicle Start 0 isapi:VMD <nil> <nil>",
		"VideoBlind Start 0 isapi:shelteralarm <nil> <nil>",
	}
	got := s.events()
	if len(got) < len(want) || strings.Join(got[:len(want)], "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
	// The remaining four are quiet-period stops of the last four intervals.
	stops := 0
	for _, event := range got[len(want):] {
		if strings.Contains(event, " Stop ") {
			stops++
		}
	}
	if stops != 4 || !s.has("identity") || !s.has("subscription") {
		t.Fatalf("stops %d, events %v", stops, got)
	}
	for _, w := range s.writes {
		if w.kind == "identity" {
			info := w.data.(map[string]any)
			if info["model"] != "DS-2CD2387G2-LU" || info["firmware"] != "V5.7.3" || info["build_date"] != "build 230101" {
				t.Fatalf("identity fields not decoded: %v", info)
			}
		}
		text := fmt.Sprint(w.data)
		if strings.Contains(text, "private-serial") || strings.Contains(text, "aa:bb:cc") || strings.Contains(text, "192.0.2.64") {
			t.Fatalf("identifying data journaled: %s", text)
		}
	}
}

func TestStalledStreamReconnects(t *testing.T) {
	h := newHik(t)
	started := time.Now()
	_, err := runUntil(t, h, func(*sink) bool { return false })
	if errors.Is(err, context.Canceled) || time.Since(started) > 4*time.Second {
		t.Fatalf("a stalled stream was not ended by the idle timeout: %v", err)
	}
}

func TestRejectedCredentialsStopTheSource(t *testing.T) {
	h := newHik(t)
	h.reject = true
	if _, err := runUntil(t, h, func(*sink) bool { return false }); !errors.Is(err, capture.ErrAuthentication) {
		t.Fatalf("err = %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streams != 0 {
		t.Fatal("stream opened without authentication")
	}
}

func TestTrackerEndsIntervalsOnInactiveOrQuiet(t *testing.T) {
	tr := newTracker(time.Second)
	now := time.Now()
	if len(tr.apply(alert{EventType: "fielddetection", EventState: "active", ChannelID: "1", TargetTypes: []string{"human", "vehicle"}}, now)) != 1 {
		t.Fatal("start missing")
	}
	if len(tr.apply(alert{EventType: "fielddetection", EventState: "active", ChannelID: "1", TargetTypes: []string{"human", "vehicle"}}, now.Add(900*time.Millisecond))) != 0 {
		t.Fatal("repeated alert restarted the interval")
	}
	if len(tr.expire(now.Add(1500*time.Millisecond))) != 0 {
		t.Fatal("refreshed interval expired early")
	}
	if ended := tr.expire(now.Add(2 * time.Second)); len(ended) != 1 || ended[0]["Action"] != "Stop" {
		t.Fatalf("ended = %v", ended)
	}
	if len(tr.apply(alert{EventType: "unknownEvent", EventState: "active"}, now)) != 0 {
		t.Fatal("unknown event mapped")
	}
}

func TestHeartbeatAndChannelVariants(t *testing.T) {
	parsed, ok := parseXML([]byte(`<EventNotificationAlert xmlns="http://www.isapi.org/ver20/XMLSchema"><channelID>1</channelID><eventType>IO</eventType><eventState>inactive</eventState><eventDescription>Heartbeat</eventDescription></EventNotificationAlert>`))
	if !ok || !parsed.heartbeat() {
		t.Fatal("heartbeat description not recognized")
	}
	for _, tc := range []struct {
		channel, dynamic string
		lens             int
	}{{"1", "", 0}, {"33", "", 32}, {"36", "", 35}, {"5", "2", 1}, {"", "", -1}, {"bad", "", -1}, {"1", "bad", -1}, {"0", "", -1}} {
		if got := (alert{ChannelID: tc.channel, DynChannelID: tc.dynamic}).lens(); got != tc.lens {
			t.Fatalf("channel %q/%q -> %d, want %d", tc.channel, tc.dynamic, got, tc.lens)
		}
	}
	if found := detections(alert{EventType: "VMDHumanVehicle", TargetTypes: []string{"human"}}); len(found) != 2 {
		t.Fatalf("VMDHumanVehicle detections = %v", found)
	}
}

func TestUnsupportedIdentityDoesNotBlockEvents(t *testing.T) {
	h := newHik(t)
	h.infoStatus = http.StatusNotFound
	h.parts <- part("application/xml", xmlAlert("VMD", "active", "1", ""))
	s, err := runUntil(t, h, func(s *sink) bool { return len(s.events()) > 0 })
	if !errors.Is(err, context.Canceled) || len(s.events()) == 0 || s.has("identity") {
		t.Fatalf("optional identity blocked subscription: events %v, err %v", s.events(), err)
	}
}

func TestChallengeBodyCannotBlockAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="hik", nonce="n1", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	c := newClient(capture.Device{Host: host, NativePort: number, Username: "admin", Password: "secret"}, time.Second)
	defer c.http.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := c.get(ctx, streamPath)
	if err != nil {
		t.Fatalf("unbounded challenge body prevented retry: %v", err)
	}
	response.Body.Close()
}

func TestSparseInactivePreservesKnownClassAndRule(t *testing.T) {
	tr := newTracker(time.Second)
	now := time.Now()
	tr.apply(alert{EventType: "fielddetection", EventState: "active", ChannelID: "2", TargetTypes: []string{"human"}, RegionIDs: []string{"7"}}, now)
	ended := tr.apply(alert{EventType: "fielddetection", EventState: "inactive", ChannelID: "2"}, now)
	if len(ended) != 1 || ended[0]["Action"] != "Stop" || fmt.Sprint(ended[0]["Data"]) != "map[ObjectTypes:[human] RuleID:7 event:isapi:fielddetection]" {
		t.Fatalf("sparse inactive lost original meaning: %v", ended)
	}
	for _, region := range []string{"1", "2"} {
		tr.apply(alert{EventType: "fielddetection", EventState: "active", ChannelID: "2", TargetTypes: []string{"human"}, RegionIDs: []string{region}}, now)
	}
	if ended := tr.apply(alert{EventType: "fielddetection", EventState: "inactive", ChannelID: "2"}, now); len(ended) != 0 || len(tr.open) != 2 {
		t.Fatalf("ambiguous inactive closed another rule: %v", ended)
	}
}

func TestSparseMotionInactiveClosesSingleClass(t *testing.T) {
	tr := newTracker(time.Second)
	now := time.Now()
	tr.apply(alert{EventType: "VMD", EventState: "active", ChannelID: "1", TargetTypes: []string{"human"}}, now)
	if ended := tr.apply(alert{EventType: "VMD", EventState: "inactive", ChannelID: "1"}, now); len(ended) != 2 || len(tr.open) != 0 {
		t.Fatalf("sparse VMD did not close generic and classified edges: %v", ended)
	}
}

func TestInactiveDoesNotEndOverlappingMotionClass(t *testing.T) {
	tr := newTracker(time.Second)
	now := time.Now()
	for _, class := range []string{"human", "vehicle"} {
		tr.apply(alert{EventType: "VMD", EventState: "active", ChannelID: "1", TargetTypes: []string{class}}, now)
	}
	if ended := tr.apply(alert{EventType: "VMD", EventState: "inactive", ChannelID: "1"}, now); len(ended) != 0 {
		t.Fatalf("ambiguous sparse inactive closed multiple classes: %v", ended)
	}
	ended := tr.apply(alert{EventType: "VMD", EventState: "inactive", ChannelID: "1", TargetTypes: []string{"human"}}, now)
	if len(ended) != 1 || ended[0]["Code"] != "SmartMotionHuman" || len(tr.open) != 2 {
		t.Fatalf("human inactive ended concurrent vehicle or generic motion: %v", ended)
	}
	ended = tr.apply(alert{EventType: "VMD", EventState: "inactive", ChannelID: "1", TargetTypes: []string{"vehicle"}}, now)
	if len(ended) != 2 || len(tr.open) != 0 {
		t.Fatalf("last inactive did not end vehicle and generic motion: %v", ended)
	}
}

func TestMalformedMultipartFramingIsBounded(t *testing.T) {
	for _, data := range []string{
		strings.Repeat("x", maxPart+1),
		"--boundary\r\nX-Long: " + strings.Repeat("x", maxPart+1),
		"--boundary\r\nContent-Type: application/xml\r\n\r\n" + strings.Repeat("x", maxPart+1),
		"--boundary\r\nContent-Length: 999999999\r\n\r\n",
		"--boundary\r\nContent-Length: -1\r\n\r\n",
	} {
		if err := readParts(strings.NewReader(data), "boundary", make(chan alert, 1), t.Context().Done()); !errors.Is(err, ErrStream) {
			t.Fatalf("malformed multipart returned %v", err)
		}
	}
}

func TestNotificationRetainsNativeTime(t *testing.T) {
	const nativeTime = "2026-10-17T10:00:00+03:00"
	xmlValue, xmlOK := parseXML([]byte(xmlAlert("VMD", "active", "1", "")))
	jsonValue, jsonOK := parseJSON([]byte(`{"eventType":"VMD","eventState":"active","dateTime":"` + nativeTime + `"}`))
	if !xmlOK || !jsonOK || xmlValue.journal()["date_time"] != nativeTime || jsonValue.journal()["date_time"] != nativeTime {
		t.Fatal("native event time was not retained in notification journal")
	}
}
