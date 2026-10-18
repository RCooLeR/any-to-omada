package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
)

// alarmControlFake records source-selection ordering and acknowledged outcomes.
type alarmControlFake struct {
	light, sound  bool
	starts, stops int
	err           error
}

// Start records the selected alarm outputs without actuating a physical device.
func (a *alarmControlFake) Start(_ context.Context, light, sound bool) (time.Duration, error) {
	a.light, a.sound = light, sound
	a.starts++
	return 2 * time.Second, a.err
}

// Stop counts priority requests and returns the configured acknowledgement error.
func (a *alarmControlFake) Stop(context.Context) error {
	a.stops++
	return a.err
}

func TestAlarmAdapterUsesActualSelectedOutputAndPriorityStop(t *testing.T) {
	mux, c, _, _ := controlFixture()
	alarm := &alarmControlFake{}
	c.outputs = &cameraOutputs{cfg: &config.Deterrence{SoundAlarm: true, LightAlarm: true, MaxAlarmSeconds: 2}, alarm: alarm, gate: c.gate}
	w := controlPost(mux, `{"command":"sound_alarm_start"}`, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"timer":2`) || !alarm.sound || alarm.light {
		t.Fatal("sound-only action did not reach the correct source output")
	}
	c.gate.busy <- struct{}{}
	if w := controlPost(mux, `{"command":"light_alarm_start"}`, nil); w.Code != http.StatusConflict || alarm.starts != 1 {
		t.Fatal("busy source admitted another alarm")
	}
	if w := controlPost(mux, `{"command":"deterrence_stop"}`, nil); w.Code != http.StatusOK || alarm.stops != 1 {
		t.Fatal("busy source blocked alarm stop")
	}
	<-c.gate.busy
	c.outputs.cfg.LightAlarm = false
	if w := controlPost(mux, `{"command":"light_alarm_start"}`, nil); w.Code != http.StatusNotImplemented || alarm.starts != 1 {
		t.Fatal("unsupported output reached source")
	}
}

func TestAlarmAdapterFailureDoesNotClaimAcknowledgement(t *testing.T) {
	mux, c, _, _ := controlFixture()
	alarm := &alarmControlFake{err: errors.Join(dvripcapture.ErrDeterrenceStop, dvripcapture.ErrDeterrenceUnsupported, errors.New("private source body"))}
	c.outputs = &cameraOutputs{cfg: &config.Deterrence{SoundAlarm: true, MaxAlarmSeconds: 2}, alarm: alarm, gate: c.gate}
	w := controlPost(mux, `{"command":"sound_alarm_start"}`, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), `"stop_unconfirmed":true`) || strings.Contains(w.Body.String(), "private") {
		t.Fatal("failed stop hidden or source body exposed")
	}
	alarm.err = capture.ErrAuthentication
	controlPost(mux, `{"command":"sound_alarm_start"}`, nil)
	controlPost(mux, `{"command":"sound_alarm_start"}`, nil)
	if alarm.starts != 2 {
		t.Fatal("authentication rejection retried during source cooldown")
	}
}
