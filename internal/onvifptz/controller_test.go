package onvifptz

import (
	"context"
	"crypto/md5"
	"encoding/hex"
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
)

// fakeCamera emulates ONVIF discovery and movement replies while recording
// operations and allowing tests to inject authentication and stop failures.
type fakeCamera struct {
	t              *testing.T
	server         *httptest.Server
	digest         bool
	password       string
	continuousZoom bool
	otherHost      bool
	noZoomStatus   bool
	noPresets      bool
	timeoutMin     string
	timeoutMax     string
	before         func(string)
	mu             sync.Mutex
	stopFailure    bool
	operations     []string
	bodies         map[string]string
	zoom           float64
	presets        map[string]string
}

var operationPattern = regexp.MustCompile(`<s:Body><t:([A-Za-z]+)>`)

// newFakeCamera starts a disposable loopback SOAP endpoint with synthetic presets.
func newFakeCamera(t *testing.T) *fakeCamera {
	f := &fakeCamera{t: t, password: "camera-secret", bodies: map[string]string{}, zoom: 0.3, presets: map[string]string{"1": "Door", "2": "Yard"}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

// controller targets the fake endpoint with a one-second movement watchdog and
// registers shutdown before the test server is cleaned up.
func (f *fakeCamera) controller(t *testing.T, password string) *Controller {
	host, portText, _ := net.SplitHostPort(f.server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	c, err := New(Config{Host: host, Port: port, Username: "admin", Password: password, ProfileToken: "Profile000", MaxMove: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// count snapshots how often an accepted operation reached the fake camera.
func (f *fakeCamera) count(operation string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, op := range f.operations {
		if op == operation {
			n++
		}
	}
	return n
}

// body returns the latest recorded SOAP payload for operation assertions.
func (f *fakeCamera) body(operation string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[operation]
}

// serve checks the expected credential form and emits configurable discovery,
// movement and preset responses without controlling a physical device.
func (f *fakeCamera) serve(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	match := operationPattern.FindStringSubmatch(body)
	if match == nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	operation := match[1]
	if f.before != nil {
		f.before(operation)
	}
	if operation != "GetSystemDateAndTime" {
		if !strings.Contains(body, "<wsse:Username>admin</wsse:Username>") || !strings.Contains(body, "PasswordDigest") || strings.Contains(body, f.password) {
			f.t.Errorf("%s lacks a UsernameToken digest or carries the plaintext password", operation)
		}
		if f.digest && !f.validDigest(r) {
			w.Header().Set("WWW-Authenticate", `Digest realm="cam", nonce="abc", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	f.mu.Lock()
	f.operations = append(f.operations, operation)
	f.bodies[operation] = body
	stopFailure := f.stopFailure
	f.mu.Unlock()
	if operation == "Stop" && stopFailure {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	reply := func(namespace, content string) {
		w.Header().Set("Content-Type", "application/soap+xml")
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:x="%s" xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body><x:%sResponse>%s</x:%sResponse></s:Body></s:Envelope>`, namespace, operation, content, operation)
	}
	switch operation {
	case "GetSystemDateAndTime":
		now := time.Now().UTC()
		reply(deviceNamespace, fmt.Sprintf(`<x:SystemDateAndTime><tt:UTCDateTime><tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time><tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date></tt:UTCDateTime></x:SystemDateAndTime>`, now.Hour(), now.Minute(), now.Second(), now.Year(), now.Month(), now.Day()))
	case "GetServices":
		base := "http://" + r.Host
		if f.otherHost {
			base = "http://192.0.2.10"
		}
		reply(deviceNamespace, `<x:Service><x:Namespace>`+mediaNamespace+`</x:Namespace><x:XAddr>`+base+`/onvif/media_service</x:XAddr></x:Service>`+
			`<x:Service><x:Namespace>`+ptzNamespace+`</x:Namespace><x:XAddr>`+base+`/onvif/ptz_service</x:XAddr></x:Service>`)
	case "GetProfile":
		reply(mediaNamespace, `<x:Profile token="Profile000"><tt:PTZConfiguration token="PTZ000"><tt:NodeToken>PTZ000</tt:NodeToken></tt:PTZConfiguration></x:Profile>`)
	case "GetNode":
		maximumPresets := "8"
		if f.noPresets {
			maximumPresets = "0"
		}
		zoom := `<tt:AbsoluteZoomPositionSpace><tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI><tt:XRange><tt:Min>0</tt:Min><tt:Max>1</tt:Max></tt:XRange></tt:AbsoluteZoomPositionSpace>`
		if f.continuousZoom {
			zoom += `<tt:ContinuousZoomVelocitySpace><tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange></tt:ContinuousZoomVelocitySpace>`
		}
		reply(ptzNamespace, `<x:PTZNode token="PTZ000"><tt:SupportedPTZSpaces>`+zoom+
			`<tt:ContinuousPanTiltVelocitySpace><tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocitySpaceDegrees</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange><tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:ContinuousPanTiltVelocitySpace>`+
			`<tt:ContinuousPanTiltVelocitySpace><tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange><tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:ContinuousPanTiltVelocitySpace>`+
			`</tt:SupportedPTZSpaces><tt:MaximumNumberOfPresets>`+maximumPresets+`</tt:MaximumNumberOfPresets><tt:HomeSupported>false</tt:HomeSupported></x:PTZNode>`)
	case "GetConfigurationOptions":
		minimum, maximum := f.timeoutMin, f.timeoutMax
		if minimum == "" {
			minimum = "PT1S"
		}
		if maximum == "" {
			maximum = "PT10S"
		}
		reply(ptzNamespace, `<x:PTZConfigurationOptions><tt:PTZTimeout><tt:Min>`+minimum+`</tt:Min><tt:Max>`+maximum+`</tt:Max></tt:PTZTimeout></x:PTZConfigurationOptions>`)
	case "GetPresets":
		f.mu.Lock()
		content := ""
		for _, token := range []string{"1", "2", "3"} {
			if name, ok := f.presets[token]; ok {
				content += `<x:Preset token="` + token + `"><tt:Name>` + name + `</tt:Name></x:Preset>`
			}
		}
		f.mu.Unlock()
		reply(ptzNamespace, content)
	case "SetPreset":
		f.mu.Lock()
		f.presets["3"] = "New"
		f.mu.Unlock()
		reply(ptzNamespace, `<x:PresetToken>3</x:PresetToken>`)
	case "GetStatus":
		if f.noZoomStatus {
			reply(ptzNamespace, `<x:PTZStatus><tt:Position><tt:PanTilt x="0" y="0" space="p"/></tt:Position><tt:MoveStatus><tt:PanTilt>IDLE</tt:PanTilt></tt:MoveStatus></x:PTZStatus>`)
			return
		}
		reply(ptzNamespace, fmt.Sprintf(`<x:PTZStatus><tt:Position><tt:Zoom x="%.2f" space="z"/></tt:Position></x:PTZStatus>`, f.zoom))
	case "GotoPreset", "RemovePreset", "ContinuousMove", "Stop", "AbsoluteMove":
		reply(ptzNamespace, "")
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// validDigest checks the fixture's fixed MD5 challenge against the SOAP request path.
func (f *fakeCamera) validDigest(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	fields := map[string]string{}
	for _, match := range regexp.MustCompile(`(\w+)="([^"]*)"`).FindAllStringSubmatch(header, -1) {
		fields[match[1]] = match[2]
	}
	hash := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	ha1, ha2 := hash("admin:cam:"+f.password), hash("POST:"+r.URL.Path)
	return fields["uri"] == r.URL.Path && fields["response"] == hash(ha1+":abc:"+fields["nc"]+":"+fields["cnonce"]+":auth:"+ha2)
}

// waitFor gives the asynchronous controller at most five seconds to reach a state.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMoveWithoutStopEndsByWatchdog(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Move(0.5, -0.25, 0)
	waitFor(t, func() bool { return camera.count("ContinuousMove") == 1 })
	body := camera.body("ContinuousMove")
	for _, want := range []string{`<tt:PanTilt x="0.500" y="-0.250" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"/>`, "<t:ProfileToken>Profile000</t:ProfileToken>", "<t:Timeout>PT1S</t:Timeout>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ContinuousMove lacks %s: %s", want, body)
		}
	}
	if strings.Contains(body, "<tt:Zoom") {
		t.Fatal("pan/tilt move addressed a zoom axis the node cannot move continuously")
	}
	waitFor(t, func() bool { s := c.Status(); return camera.count("Stop") == 1 && s.Stops == 1 && !s.Moving })
	if status := c.Status(); status.WatchdogStops != 1 || status.Moves != 1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestRecorderStopEndsMovementOnce(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Move(-1, 0, 0)
	waitFor(t, func() bool { return camera.count("ContinuousMove") == 1 })
	c.Stop()
	waitFor(t, func() bool { return camera.count("Stop") == 1 })
	c.Stop()
	time.Sleep(1300 * time.Millisecond)
	if camera.count("Stop") != 1 || c.Status().WatchdogStops != 0 {
		t.Fatalf("stops = %d, status %+v", camera.count("Stop"), c.Status())
	}
	if body := camera.body("Stop"); !strings.Contains(body, "<t:PanTilt>true</t:PanTilt><t:Zoom>true</t:Zoom>") {
		t.Fatalf("Stop body: %s", body)
	}
}

func TestCloseStopsMovingCamera(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Move(0, 1, 0)
	waitFor(t, func() bool { return camera.count("ContinuousMove") == 1 })
	c.Close()
	if camera.count("Stop") != 1 {
		t.Fatal("close left the camera moving")
	}
}

func TestContinuousZoomAndAbsoluteZoomStep(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Move(0, 0, 1)
	waitFor(t, func() bool { return camera.count("AbsoluteMove") == 1 })
	if body := camera.body("AbsoluteMove"); !strings.Contains(body, `<tt:Zoom x="0.400" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"/>`) || strings.Contains(body, "PanTilt") {
		t.Fatalf("zoom step: %s", body)
	}
	if camera.count("ContinuousMove") != 0 || !c.Status().Moving {
		t.Fatal("absolute zoom must be tracked for Stop without starting ContinuousMove")
	}
	c.Stop()
	waitFor(t, func() bool { return camera.count("Stop") == 1 && !c.Status().Moving })

	continuous := newFakeCamera(t)
	continuous.continuousZoom = true
	c = continuous.controller(t, continuous.password)
	capability, err := c.Capability(context.Background())
	if err != nil || !capability.ContinuousZoom || !capability.Zoom || !capability.PanTilt || capability.MaxPresets != 8 || capability.Home {
		t.Fatalf("capability = %+v, %v", capability, err)
	}
	c.Move(0, 0, -0.5)
	waitFor(t, func() bool { return continuous.count("ContinuousMove") == 1 })
	if body := continuous.body("ContinuousMove"); !strings.Contains(body, `<tt:Zoom x="-0.500" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace"/>`) {
		t.Fatalf("zoom move: %s", body)
	}
}

func TestAdvertisedZoomSpaceWithoutZoomPositionIsNotZoom(t *testing.T) {
	camera := newFakeCamera(t)
	camera.noZoomStatus = true
	c := camera.controller(t, camera.password)
	capability, err := c.Capability(context.Background())
	if err != nil || capability.Zoom || !capability.PanTilt {
		t.Fatalf("capability = %+v, %v", capability, err)
	}
	c.Move(0, 0, 1)
	time.Sleep(200 * time.Millisecond)
	if camera.count("AbsoluteMove") != 0 || camera.count("ContinuousMove") != 0 || c.Status().LastFailure != "move:unsupported" {
		t.Fatalf("zoom without a zoom lens was sent: %+v", c.Status())
	}
}

func TestPresets(t *testing.T) {
	camera := newFakeCamera(t)
	camera.digest = true
	c := camera.controller(t, camera.password)
	ctx := context.Background()
	presets, err := c.Presets(ctx)
	if err != nil || len(presets) != 2 || presets[0] != (Preset{"1", "Door"}) || presets[1] != (Preset{"2", "Yard"}) {
		t.Fatalf("presets = %+v, %v", presets, err)
	}
	if err := c.GotoPreset(ctx, "2"); err != nil || !strings.Contains(camera.body("GotoPreset"), "<t:PresetToken>2</t:PresetToken>") {
		t.Fatalf("goto: %v", err)
	}
	token, err := c.SetPreset(ctx, "Gate <1>", "")
	if err != nil || token != "3" || !strings.Contains(camera.body("SetPreset"), "<t:PresetName>Gate &lt;1&gt;</t:PresetName>") {
		t.Fatalf("set: %q %v", token, err)
	}
	if err := c.RemovePreset(ctx, "1"); err != nil || !strings.Contains(camera.body("RemovePreset"), "<t:PresetToken>1</t:PresetToken>") {
		t.Fatalf("remove: %v", err)
	}
	if err := c.GotoPreset(ctx, "1</t:PresetToken>"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsafe token accepted: %v", err)
	}
}

func TestRejectedCredentialsStartCooldown(t *testing.T) {
	camera := newFakeCamera(t)
	camera.digest = true
	c := camera.controller(t, "wrong-password")
	if _, err := c.Presets(context.Background()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(fmt.Sprint(c.Status()), "wrong-password") {
		t.Fatal("status leaked the password")
	}
	before := len(camera.operations)
	c.mu.Lock()
	c.retryAfter = time.Time{}
	c.mu.Unlock()
	if _, err := c.Presets(context.Background()); !errors.Is(err, ErrAuthentication) || len(camera.operations) != before {
		t.Fatalf("cooldown did not block a new attempt: %v", err)
	}
}

func TestDiscoveryRejectsServicesOnOtherHosts(t *testing.T) {
	camera := newFakeCamera(t)
	camera.otherHost = true
	c := camera.controller(t, camera.password)
	if _, err := c.Capability(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if camera.count("GetProfile") != 0 {
		t.Fatal("discovery followed a service address on another host")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []Config{
		{Host: "camera.local", Port: 80, Username: "admin", Password: "p", ProfileToken: "Profile000"},
		{Host: "10.0.0.1", Port: 0, Username: "admin", Password: "p", ProfileToken: "Profile000"},
		{Host: "10.0.0.1", Port: 80, Username: "admin", Password: "p", ProfileToken: "bad token"},
		{Host: "10.0.0.1", Port: 80, Username: "admin", Password: "p", ProfileToken: "Profile000", MaxMove: time.Hour},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
}

func TestCameraMinimumDoesNotOverrideLocalWatchdog(t *testing.T) {
	camera := newFakeCamera(t)
	camera.timeoutMin, camera.timeoutMax = "PT180S", "PT180S"
	c := camera.controller(t, camera.password)
	c.Move(0.5, 0, 0)
	waitFor(t, func() bool { return camera.count("ContinuousMove") == 1 })
	if !strings.Contains(camera.body("ContinuousMove"), "<t:Timeout>PT180S</t:Timeout>") {
		t.Fatal("camera timeout must remain within the camera's advertised range")
	}
	// waitFor is bounded to five seconds: waiting for the camera's 180-second
	// timeout cannot satisfy this check of the configured one-second watchdog.
	waitFor(t, func() bool { return camera.count("Stop") == 1 && !c.Status().Moving })
	if c.Status().WatchdogStops != 1 {
		t.Fatalf("local watchdog did not stop the camera: %+v", c.Status())
	}
}

func TestPresetMovementUsesRecorderStopShutdownAndWatchdog(t *testing.T) {
	for _, ending := range []string{"recorder", "shutdown", "watchdog"} {
		t.Run(ending, func(t *testing.T) {
			camera := newFakeCamera(t)
			c := camera.controller(t, camera.password)
			if err := c.GotoPreset(t.Context(), "1"); err != nil {
				t.Fatal(err)
			}
			if !c.Status().Moving || c.Status().Moves != 1 || camera.count("GotoPreset") != 1 {
				t.Fatalf("preset movement is not tracked: %+v", c.Status())
			}
			switch ending {
			case "recorder":
				c.Stop()
			case "shutdown":
				c.Close()
			}
			waitFor(t, func() bool { return camera.count("Stop") == 1 && !c.Status().Moving })
			if ending == "watchdog" && c.Status().WatchdogStops != 1 {
				t.Fatalf("preset watchdog did not run: %+v", c.Status())
			}
		})
	}
}

func TestStopDuringDiscoveryPreventsStaleMovement(t *testing.T) {
	for _, movement := range []string{"continuous", "preset"} {
		t.Run(movement, func(t *testing.T) {
			camera := newFakeCamera(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			camera.before = func(operation string) {
				if operation == "GetProfile" {
					once.Do(func() { close(entered) })
					<-release
				}
			}
			c := camera.controller(t, camera.password)
			defer close(release)
			result := make(chan error, 1)
			if movement == "preset" {
				go func() { result <- c.GotoPreset(t.Context(), "1") }()
			} else {
				c.Move(0.5, 0, 0)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("discovery did not start")
			}
			c.Stop()
			waitFor(t, func() bool {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.pending == nil && c.activeCancel == nil && c.status.Failures > 0
			})
			if movement == "preset" {
				select {
				case err := <-result:
					if !errors.Is(err, ErrUnavailable) {
						t.Fatalf("superseded preset = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("superseded preset caller was left waiting")
				}
			}
			if camera.count("ContinuousMove") != 0 || camera.count("GotoPreset") != 0 || c.Status().Moving {
				t.Fatalf("superseded command moved the camera: %+v", c.Status())
			}
		})
	}
}

func TestFailedStopKeepsUncertainMovementAndCanRecover(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	if err := c.GotoPreset(t.Context(), "1"); err != nil {
		t.Fatal(err)
	}
	camera.mu.Lock()
	camera.stopFailure = true
	camera.mu.Unlock()
	c.Stop()
	waitFor(t, func() bool { return c.Status().LastFailure == "stop:unavailable" })
	if !c.Status().Moving || c.Status().Stops != 0 {
		t.Fatalf("failed Stop falsely reported a stopped camera: %+v", c.Status())
	}
	camera.mu.Lock()
	camera.stopFailure = false
	camera.mu.Unlock()
	c.Close()
	if c.Status().Moving || c.Status().Stops != 1 {
		t.Fatalf("shutdown did not retry the uncertain Stop: %+v", c.Status())
	}
}

func TestClosedControllerCannotMoveByPreset(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Close()
	if err := c.GotoPreset(t.Context(), "1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed controller preset = %v", err)
	}
	if camera.count("GetServices") != 0 || camera.count("GotoPreset") != 0 {
		t.Fatal("closed controller contacted the camera")
	}
}

func TestMixedAbsoluteZoomDoesNotSilentlyDiscardPanTilt(t *testing.T) {
	camera := newFakeCamera(t)
	c := camera.controller(t, camera.password)
	c.Move(0.5, 0.25, 0.5)
	waitFor(t, func() bool { return c.Status().LastFailure == "move:unsupported" })
	if camera.count("ContinuousMove") != 0 || camera.count("AbsoluteMove") != 0 || c.Status().Moving {
		t.Fatalf("mixed unsupported command partly executed: %+v", c.Status())
	}
}

func TestPresetUnsupportedByDiscoveredNodeIsNotSent(t *testing.T) {
	camera := newFakeCamera(t)
	camera.noPresets = true
	c := camera.controller(t, camera.password)
	if err := c.GotoPreset(t.Context(), "1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("preset on unsupported node = %v", err)
	}
	if camera.count("GotoPreset") != 0 || c.Status().Moving {
		t.Fatalf("unsupported preset reached camera: %+v", c.Status())
	}
}
