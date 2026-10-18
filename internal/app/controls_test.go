package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
)

type controlPTZFake struct {
	moves, stops int
	err          error
}

func (p *controlPTZFake) Capability(context.Context) (onvifptz.Capability, error) {
	return onvifptz.Capability{PanTilt: true}, p.err
}
func (p *controlPTZFake) Move(float64, float64, float64) { p.moves++ }
func (p *controlPTZFake) Stop()                          { p.stops++ }

type controlLightFake struct {
	pulses int
	err    error
}

func (l *controlLightFake) Available(context.Context, int, int) error { return l.err }
func (l *controlLightFake) Pulse(context.Context, int, int, int, time.Duration) error {
	l.pulses++
	return l.err
}

func controlFixture() (*http.ServeMux, *cameraControls, *controlPTZFake, *controlLightFake) {
	ptz, light := &controlPTZFake{}, &controlLightFake{}
	c := &cameraControls{cfg: config.Camera{WhiteLight: &config.WhiteLight{Profile: 0, Brightness: 50}}, ptz: ptz, light: light, gate: &sourceControlGate{busy: make(chan struct{}, 1)}}
	mux := http.NewServeMux()
	registerControls(mux, map[string]*cameraControls{"test": c})
	return mux, c, ptz, light
}
func controlPost(mux *http.ServeMux, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19031/api/v1/cameras/test/controls", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		if key == "Host" {
			r.Host = value
		} else {
			r.Header.Set(key, value)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestControlAPIRejectsBrowserOriginInvalidInputsAndUnsupportedZoom(t *testing.T) {
	mux, _, ptz, light := controlFixture()
	for _, headers := range []map[string]string{{"Origin": "https://example.test"}, {"Sec-Fetch-Site": "cross-site"}, {"Host": "example.test:19031"}, {"Content-Type": "text/plain"}} {
		if w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, headers); w.Code < 400 {
			t.Fatal("browser request accepted")
		}
	}
	for _, body := range []string{`{"command":"ptz_move","pan":2}`, `{"command":"ptz_move"}`, `{"command":"ptz_stop","duration_ms":100}`, `{"command":"white_light_pulse","duration_ms":5001}`, `{"command":"alarm_pulse","url":"http://example.test"}`, `{"command":"ptz_stop"}{}`} {
		if w := controlPost(mux, body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid request accepted: %d", w.Code)
		}
	}
	if w := controlPost(mux, `{"command":"ptz_move","zoom":0.5}`, nil); w.Code != http.StatusNotImplemented {
		t.Fatal("unsupported zoom accepted")
	}
	if ptz.moves != 0 || ptz.stops != 0 || light.pulses != 0 {
		t.Fatal("invalid request actuated source")
	}
}

func TestControlAPIPTZQueuedAndStopBypassesBusyGate(t *testing.T) {
	mux, c, ptz, _ := controlFixture()
	if w := controlPost(mux, `{"command":"ptz_move","pan":0.2}`, nil); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "move_queued") {
		t.Fatal("move not reported queued")
	}
	c.gate.busy <- struct{}{}
	if w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, nil); w.Code != http.StatusConflict {
		t.Fatal("overlapping output pulse accepted")
	}
	if w := controlPost(mux, `{"command":"ptz_stop"}`, nil); w.Code != http.StatusAccepted {
		t.Fatal("busy gate blocked stop")
	}
	<-c.gate.busy
	if ptz.moves != 1 || ptz.stops != 1 {
		t.Fatal("incorrect PTZ requests")
	}
}

func TestControlAPIFailureNeverClaimsRestorationOrLeaksError(t *testing.T) {
	mux, _, _, light := controlFixture()
	light.err = errors.New("secret-bearing upstream error")
	w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "unconfirmed") || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("incorrect sanitized failure")
	}
	if w := controlPost(mux, `{"command":"alarm_pulse"}`, nil); w.Code != http.StatusNotImplemented {
		t.Fatal("absent relay pretends to be siren")
	}
	light.err = errors.Join(dvripcapture.ErrLightingUnsupported, dvripcapture.ErrLightingRestore)
	if w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, nil); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "unconfirmed") {
		t.Fatal("unsupported error hid failed restoration")
	}
}

func TestControlAPIAuthenticationCooldownCoversOtherControlClients(t *testing.T) {
	mux, _, ptz, light := controlFixture()
	ptz.err = onvifptz.ErrAuthentication
	controlPost(mux, `{"command":"ptz_move","pan":0.2}`, nil)
	if w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, nil); w.Code != http.StatusServiceUnavailable || light.pulses != 0 {
		t.Fatal("shared source authentication cooldown bypassed")
	}
}

func TestControlAPIReturnsTypedLightingDiagnosticWithoutRawErrors(t *testing.T) {
	mux, _, _, light := controlFixture()
	code := int64(268632079)
	light.err = errors.Join(&dvripcapture.LightingError{Operation: "configManager.setConfig", Stage: "rejected", DeviceCode: &code}, dvripcapture.ErrLightingRestore, errors.New("secret camera fault body"))
	w := controlPost(mux, `{"command":"white_light_pulse","duration_ms":100}`, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), `"operation":"configManager.setConfig"`) || !strings.Contains(w.Body.String(), `"device_code":268632079`) || !strings.Contains(w.Body.String(), `"restoration_failed":true`) || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("incorrect sanitized diagnostics: %s", w.Body.String())
	}
}
