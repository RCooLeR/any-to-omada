package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/onvifoutput"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
	"github.com/RCooLeR/any-to-omada/internal/onvifsoap"
)

// ptzControl is the source controller contract needed by the loopback operator API.
type ptzControl interface {
	// Capability discovers supported axes or returns a source availability error.
	Capability(context.Context) (onvifptz.Capability, error)
	// Move queues normalized pan, tilt, and zoom velocities; it does not confirm actuation.
	Move(float64, float64, float64)
	// Stop queues a priority stop without waiting for a source acknowledgement.
	Stop()
}

// lightControl scopes discovery and bounded test pulses to a source lens and profile.
type lightControl interface {
	// Available checks the selected zero-based channel and profile without changing settings.
	Available(context.Context, int, int) error
	// Pulse applies brightness to the selected channel/profile for a bounded duration,
	// then attempts restoration even after cancellation or an uncertain activation reply.
	Pulse(context.Context, int, int, int, time.Duration) error
}

// relayControl exposes only an explicitly selected relay with a device-side reset timer.
type relayControl interface {
	// Available checks advertised relay support without changing its configuration.
	Available(context.Context) error
	// Pulse activates the relay once and attempts deactivation after its timer or cancellation.
	Pulse(context.Context) error
}

// sourceControlGate serializes output tests for the physical source, including
// different virtual lenses. It also suppresses repeated rejected credentials.
type sourceControlGate struct {
	busy         chan struct{}
	blockedUntil time.Time // Accessed only while busy is held.
}

// cameraControls binds explicitly configured physical control clients to one virtual lens
// and its shared source admission gate.
type cameraControls struct {
	cfg     config.Camera
	ptz     ptzControl
	light   lightControl
	relay   relayControl
	outputs *cameraOutputs
	gate    *sourceControlGate
}

// prepareControls wires only opt-in source clients without contacting the camera; output
// tests for all source lenses share one gate.
func prepareControls(cam *camera, source config.Source, password string, gate *sourceControlGate) *cameraControls {
	control := &cameraControls{cfg: cam.cfg, gate: gate}
	if cam.ptz != nil {
		control.ptz = cam.ptz
	}
	if cam.cfg.WhiteLight != nil {
		light := dvripcapture.NewLighting(capture.Device{ID: source.ID, Host: source.Host, NativePort: source.NativePort, Username: source.Account.Username, Password: password})
		control.light = light
		if len(cam.cfg.WhiteLight.RecorderModes) > 0 {
			control.light = manualLightControl{light}
		}
	}
	if output := cam.cfg.AlarmOutput; output != nil {
		cam.relay = onvifoutput.New(source.Host, output.ONVIFPort, source.Account.Username, password, output.RelayToken)
		control.relay = cam.relay
	}
	if cam.deterrence != nil {
		control.outputs = &cameraOutputs{cfg: cam.cfg.Deterrence, alarm: cam.deterrence, gate: gate}
	}
	return control
}

// manualLightControl uses the same capability-gated source bank and restoration
// contract for loopback tests as persistent recorder illumination settings.
type manualLightControl struct{ light *dvripcapture.Lighting }

// Available checks the actual lamp bank and fixed active profile without writes.
func (c manualLightControl) Available(ctx context.Context, channel, profile int) error {
	return c.light.ManualAvailable(ctx, channel, profile)
}

// Pulse temporarily applies manual white illumination and restores its lease.
func (c manualLightControl) Pulse(ctx context.Context, channel, profile, brightness int, duration time.Duration) error {
	return c.light.ManualPulse(ctx, channel, profile, brightness, duration)
}

// registerControls adds loopback operator endpoints and returns a shutdown barrier that
// stops admission before waiting for active controls.
func registerControls(mux *http.ServeMux, controls map[string]*cameraControls) func() {
	// Admission closes before Wait, preventing an Add racing an empty Wait.
	var admission sync.Mutex
	var active sync.WaitGroup
	closing := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		admission.Lock()
		if closing {
			admission.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		active.Add(1)
		admission.Unlock()
		defer active.Done()
		// This is a local operator API, not a browser or recorder endpoint.
		// JSON plus rejected browser-origin requests prevents cross-site posts
		// from using the unauthenticated loopback listener as a control proxy.
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "local_operator_only"})
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "loopback_host_required"})
			return
		}
		control := controls[r.PathValue("camera")]
		if control == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "camera_unavailable"})
			return
		}
		if r.Method == http.MethodGet {
			// GET is passive: probing is explicit so ordinary status polling
			// cannot repeatedly authenticate to camera control services.
			writeJSON(w, http.StatusOK, map[string]any{"ptz_configured": control.ptz != nil, "white_light_configured": control.light != nil,
				"alarm_output_configured": control.relay != nil, "sound_alarm_configured": control.outputs.Capabilities().SoundAlarm,
				"light_alarm_configured": control.outputs.Capabilities().LightAlarm, "hardware_verified": false, "nvr_ui_controls": "configured_controls_only"})
			return
		}
		control.handle(w, r)
	}
	mux.HandleFunc("GET /api/v1/cameras/{camera}/controls", handler)
	mux.HandleFunc("POST /api/v1/cameras/{camera}/controls", handler)
	return func() {
		admission.Lock()
		closing = true
		admission.Unlock()
		active.Wait()
	}
}

// controlRequest distinguishes omitted axes and duration from zero values for
// command-specific validation; pulse duration is in milliseconds.
type controlRequest struct {
	Command    string   `json:"command"`
	Pan        *float64 `json:"pan,omitempty"`
	Tilt       *float64 `json:"tilt,omitempty"`
	Zoom       *float64 `json:"zoom,omitempty"`
	DurationMS *int     `json:"duration_ms,omitempty"`
}

// handle validates a bounded JSON command, serializes source tests, and applies
// authentication cooldowns; an explicit PTZ stop bypasses the busy gate.
func (c *cameraControls) handle(w http.ResponseWriter, r *http.Request) {
	typeName, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "application_json_required"})
		return
	}
	var request controlRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !request.valid() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_control_request"})
		return
	}
	if request.Command == "ptz_stop" {
		if c.ptz == nil {
			controlResult(w, errControlUnsupported)
			return
		}
		c.ptz.Stop()
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "stop_queued"})
		return
	}
	if request.Command == "sound_alarm_start" || request.Command == "light_alarm_start" || request.Command == "deterrence_start" || request.Command == "deterrence_stop" {
		c.handleAlarm(w, r, request.Command)
		return
	}
	select {
	case c.gate.busy <- struct{}{}:
		defer func() { <-c.gate.busy }()
	default:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "source_control_busy"})
		return
	}
	if time.Now().Before(c.gate.blockedUntil) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "source_authentication_cooldown"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	err = errControlUnsupported
	switch request.Command {
	case "ptz_move":
		if c.ptz != nil {
			var capability onvifptz.Capability
			capability, err = c.ptz.Capability(ctx)
			if err == nil {
				pan, tilt, zoom := number(request.Pan), number(request.Tilt), number(request.Zoom)
				if ((pan != 0 || tilt != 0) && !capability.PanTilt) || (zoom != 0 && !capability.Zoom) {
					err = errControlUnsupported
				} else {
					c.ptz.Move(pan, tilt, zoom)
					writeJSON(w, http.StatusAccepted, map[string]any{"state": "move_queued"})
					return
				}
			}
		}
	case "white_light_probe":
		if c.light != nil {
			err = c.light.Available(ctx, c.cfg.SourceIndex, c.cfg.WhiteLight.Profile)
		}
	case "white_light_pulse":
		if c.light != nil {
			err = c.light.Pulse(ctx, c.cfg.SourceIndex, c.cfg.WhiteLight.Profile, c.cfg.WhiteLight.Brightness, time.Duration(*request.DurationMS)*time.Millisecond)
		}
	case "alarm_probe":
		if c.relay != nil {
			err = c.relay.Available(ctx)
		}
	case "alarm_pulse":
		if c.relay != nil {
			err = c.relay.Pulse(ctx)
		}
	}
	if errors.Is(err, capture.ErrAuthentication) || errors.Is(err, onvifptz.ErrAuthentication) || errors.Is(err, onvifsoap.ErrAuthentication) {
		c.gate.blockedUntil = time.Now().Add(time.Minute)
	}
	controlResult(w, err)
}

var errControlUnsupported = errors.New("control unsupported")

// controlResult maps source outcomes to bounded operator responses and marks failed physical
// actions as having an unconfirmed final state.
func controlResult(w http.ResponseWriter, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "completed"})
		return
	}
	response := map[string]any{}
	if errors.Is(err, errSourceControlBusy) || errors.Is(err, dvripcapture.ErrDeterrenceBusy) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "source_control_busy"})
		return
	}
	var lighting *dvripcapture.LightingError
	if errors.As(err, &lighting) {
		// This type contains fixed operation/stage labels and an optional
		// numeric device code only; never return arbitrary upstream errors.
		response["diagnostic"] = lighting
	}
	if !errors.Is(err, dvripcapture.ErrLightingRestore) && !errors.Is(err, dvripcapture.ErrDeterrenceStop) && (errors.Is(err, errControlUnsupported) || errors.Is(err, dvripcapture.ErrLightingUnsupported) || errors.Is(err, onvifoutput.ErrUnsupported) || errors.Is(err, dvripcapture.ErrDeterrenceUnsupported)) {
		response["error"] = "control_unavailable"
		writeJSON(w, http.StatusNotImplemented, response)
		return
	}
	// Source exceptions and fault bodies never reach clients or logs. On
	// failure, callers must treat the final physical output as unconfirmed.
	response["error"], response["final_state"] = "source_control_failed", "unconfirmed"
	if errors.Is(err, dvripcapture.ErrLightingRestore) {
		response["restoration_failed"] = true
	}
	if errors.Is(err, dvripcapture.ErrDeterrenceStop) {
		response["stop_unconfirmed"] = true
	}
	writeJSON(w, http.StatusBadGateway, response)
}

// number supplies zero velocity for an omitted optional PTZ axis.
func number(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

// valid accepts only command-specific fields, axes in -1..1, and white-light pulse durations
// of 100..5000 milliseconds.
func (r controlRequest) valid() bool {
	if r.Command == "ptz_move" {
		if r.DurationMS != nil || (r.Pan == nil && r.Tilt == nil && r.Zoom == nil) {
			return false
		}
		for _, value := range []*float64{r.Pan, r.Tilt, r.Zoom} {
			if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < -1 || *value > 1) {
				return false
			}
		}
		return true
	}
	if r.Pan != nil || r.Tilt != nil || r.Zoom != nil {
		return false
	}
	if r.Command == "white_light_pulse" {
		return r.DurationMS != nil && *r.DurationMS >= 100 && *r.DurationMS <= 5000
	}
	return r.DurationMS == nil && (r.Command == "ptz_stop" || r.Command == "white_light_probe" || r.Command == "alarm_probe" || r.Command == "alarm_pulse" ||
		r.Command == "sound_alarm_start" || r.Command == "light_alarm_start" || r.Command == "deterrence_start" || r.Command == "deterrence_stop")
}

// handleAlarm shares the authenticated recorder's bounded native alarm path.
// Successful starts report source acknowledgement, not measured physical state.
func (c *cameraControls) handleAlarm(w http.ResponseWriter, r *http.Request, command string) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if command == "deterrence_stop" {
		controlResult(w, c.outputs.StopAlarm(ctx))
		return
	}
	capability := c.outputs.Capabilities()
	sound := command == "sound_alarm_start" || (command == "deterrence_start" && capability.SoundAlarm)
	light := command == "light_alarm_start" || (command == "deterrence_start" && capability.LightAlarm)
	seconds, err := c.outputs.StartAlarm(ctx, sound, light)
	if err != nil {
		controlResult(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "source_acknowledged", "timer": seconds})
}
