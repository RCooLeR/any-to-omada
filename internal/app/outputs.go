package app

import (
	"context"
	"errors"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
)

// alarmControl owns acknowledged, bounded native alarm actions and their Stop
// watchdog. Its Stop method can interrupt an in-flight Start.
type alarmControl interface {
	Start(context.Context, bool, bool) (time.Duration, error)
	Stop(context.Context) error
}

// cameraOutputs adapts explicit source output permissions to native recorder
// controls. Source activation rechecks hardware capabilities before sending ON.
type cameraOutputs struct {
	cfg   *config.Deterrence
	alarm alarmControl
	gate  *sourceControlGate
}

// Capabilities reports only configured manual outputs; steady illumination is
// separate from CoaxialControlIO's alarm light and remains unadvertised here.
func (c *cameraOutputs) Capabilities() omadafront.OutputCapability {
	if c == nil || c.cfg == nil || c.alarm == nil {
		return omadafront.OutputCapability{}
	}
	return omadafront.OutputCapability{SoundAlarm: c.cfg.SoundAlarm, LightAlarm: c.cfg.LightAlarm,
		AlarmDuration: time.Duration(c.cfg.MaxAlarmSeconds) * time.Second}
}

// WhiteLight rejects steady illumination until a source implementation is bound.
func (c *cameraOutputs) WhiteLight(context.Context, bool) error { return errControlUnsupported }

// WhiteLightState never turns an unavailable source state into an OFF readback.
func (c *cameraOutputs) WhiteLightState(context.Context) (bool, error) {
	return false, errControlUnsupported
}

// StartAlarm serializes source admission and returns a source-acknowledged
// duration. It never retries an uncertain activation or rejected credentials.
func (c *cameraOutputs) StartAlarm(ctx context.Context, sound, light bool) (int, error) {
	if c == nil || c.cfg == nil || c.alarm == nil || (!sound && !light) || (sound && !c.cfg.SoundAlarm) || (light && !c.cfg.LightAlarm) {
		return 0, errControlUnsupported
	}
	select {
	case c.gate.busy <- struct{}{}:
		defer func() { <-c.gate.busy }()
	default:
		return 0, errSourceControlBusy
	}
	if time.Now().Before(c.gate.blockedUntil) {
		return 0, capture.ErrAuthentication
	}
	duration, err := c.alarm.Start(ctx, light, sound)
	if errors.Is(err, capture.ErrAuthentication) {
		c.gate.blockedUntil = time.Now().Add(time.Minute)
	}
	if err != nil {
		return 0, err
	}
	return int(duration / time.Second), nil
}

// StopAlarm bypasses source admission so a pending activation or another
// control cannot suppress termination of an output we own.
func (c *cameraOutputs) StopAlarm(ctx context.Context) error {
	if c == nil || c.alarm == nil {
		return errControlUnsupported
	}
	return c.alarm.Stop(ctx)
}

var errSourceControlBusy = errors.New("source control busy")
