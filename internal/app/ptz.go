package app

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripptz"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
)

// ptzController is the common bounded source-control contract. Native DVRIP
// implementations reject preset methods instead of advertising unsupported work.
type ptzController interface {
	// Capability reads source-supported axes without moving the camera.
	Capability(context.Context) (onvifptz.Capability, error)
	// Move queues bounded normalized movement; receipt is not device acknowledgement.
	Move(float64, float64, float64)
	// Stop prioritizes stopping any acknowledged or uncertain movement.
	Stop()
	// Status reports local counters and unresolved physical movement.
	Status() onvifptz.Status
	// Close stops the worker and attempts bounded physical cleanup.
	Close()
	// Presets lists source positions where that backend supports them.
	Presets(context.Context) ([]onvifptz.Preset, error)
	// GotoPreset recalls a supported source position with bounded cleanup.
	GotoPreset(context.Context, string) error
	// SetPreset saves a supported source position and returns its native token.
	SetPreset(context.Context, string, string) (string, error)
	// RemovePreset deletes a source position only on backends supporting presets.
	RemovePreset(context.Context, string) error
}

// newPTZ prepares a lens controller with the configured source account. Camera
// discovery and actuation begin only when a caller requests controls or capabilities.
func newPTZ(camera config.Camera, source config.Source, password string, logger *slog.Logger) (ptzController, error) {
	if camera.PTZ.Backend == "dvrip" {
		return dvripptz.New(dvripptz.Config{Device: capture.Device{ID: source.ID, Host: source.Host, NativePort: source.NativePort, Username: source.Account.Username, Password: password},
			Channel: camera.SourceIndex, MaxMove: time.Duration(camera.PTZ.MaxMoveSeconds) * time.Second, Logger: logger})
	}
	return onvifptz.New(onvifptz.Config{Host: source.Host, Port: camera.PTZ.ONVIFPort, Username: source.Account.Username, Password: password,
		ProfileToken: camera.PTZ.ProfileToken, MaxMove: time.Duration(camera.PTZ.MaxMoveSeconds) * time.Second, Logger: logger})
}

// ptzAdapter presents ONVIF presets to the recorder by number: a numeric
// camera token is its own number; other tokens cannot be addressed and are left
// out instead of being renumbered.
type ptzAdapter struct {
	controller ptzController
	logger     *slog.Logger
}

// Capability converts source-reported ONVIF controls to the virtual management contract
// without inventing unsupported axes.
func (a ptzAdapter) Capability(ctx context.Context) (omadafront.PTZCapability, error) {
	capability, err := a.controller.Capability(ctx)
	if err != nil {
		return omadafront.PTZCapability{}, err
	}
	return omadafront.PTZCapability{PanTilt: capability.PanTilt, Zoom: capability.Zoom, MaxPresets: capability.MaxPresets, Home: capability.Home}, nil
}

// Move queues normalized pan, tilt, and zoom velocities for the controller; returning does
// not confirm physical movement.
func (a ptzAdapter) Move(pan, tilt, zoom float64) { a.controller.Move(pan, tilt, zoom) }

// Stop queues a priority stop through the source controller without claiming device
// acknowledgement.
func (a ptzAdapter) Stop() { a.controller.Stop() }

// Presets exposes only numeric source tokens from 1 to 65535, preserving their IDs and
// omitting unaddressable tokens.
func (a ptzAdapter) Presets(ctx context.Context) ([]omadafront.PTZPreset, error) {
	presets, err := a.controller.Presets(ctx)
	if err != nil {
		a.logger.Warn("ptz presets unavailable", "failure", onvifptz.ErrorClass(err))
		return nil, err
	}
	result := make([]omadafront.PTZPreset, 0, len(presets))
	skipped := 0
	for _, preset := range presets {
		id, err := strconv.Atoi(preset.Token)
		if err != nil || id < 1 || id > 65535 {
			skipped++
			continue
		}
		result = append(result, omadafront.PTZPreset{ID: id, Name: preset.Name})
	}
	a.logger.Info("ptz presets listed", "presets", len(result), "unaddressable", skipped)
	return result, nil
}

// GotoPreset addresses a positive recorder preset ID as the same numeric ONVIF token and
// logs a sanitized outcome.
func (a ptzAdapter) GotoPreset(ctx context.Context, id int) error {
	if id < 1 {
		return onvifptz.ErrUnsupported
	}
	return a.logged("goto_preset", a.controller.GotoPreset(ctx, strconv.Itoa(id)))
}

// SetPreset creates or replaces a source preset and requires a positive numeric token before
// exposing the result to the recorder.
func (a ptzAdapter) SetPreset(ctx context.Context, id int, name string) (int, error) {
	token := ""
	if id > 0 {
		token = strconv.Itoa(id)
	}
	saved, err := a.controller.SetPreset(ctx, name, token)
	if err != nil {
		return 0, a.logged("set_preset", err)
	}
	number, err := strconv.Atoi(saved)
	if err != nil || number < 1 {
		return 0, a.logged("set_preset", onvifptz.ErrUnavailable)
	}
	return number, a.logged("set_preset", nil)
}

// RemovePreset removes the source preset with the matching positive numeric token.
func (a ptzAdapter) RemovePreset(ctx context.Context, id int) error {
	if id < 1 {
		return onvifptz.ErrUnsupported
	}
	return a.logged("remove_preset", a.controller.RemovePreset(ctx, strconv.Itoa(id)))
}

// logged reports a fixed PTZ operation and error class while returning the original error to
// its caller.
func (a ptzAdapter) logged(operation string, err error) error {
	if err != nil {
		a.logger.Warn("ptz command failed", "operation", operation, "failure", onvifptz.ErrorClass(err))
	} else {
		a.logger.Info("ptz command sent", "operation", operation)
	}
	return err
}
