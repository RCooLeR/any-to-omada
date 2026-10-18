package app

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
)

// newPTZ connects a ptz lens to its source's ONVIF PTZ service with the source
// account. It contacts the camera only when the recorder sends a command.
func newPTZ(camera config.Camera, source config.Source, password string, logger *slog.Logger) (*onvifptz.Controller, error) {
	return onvifptz.New(onvifptz.Config{Host: source.Host, Port: camera.PTZ.ONVIFPort, Username: source.Account.Username, Password: password,
		ProfileToken: camera.PTZ.ProfileToken, MaxMove: time.Duration(camera.PTZ.MaxMoveSeconds) * time.Second, Logger: logger})
}

// ptzAdapter presents ONVIF presets to the recorder by number: a numeric
// camera token is its own number; other tokens cannot be addressed and are left
// out instead of being renumbered.
type ptzAdapter struct {
	controller *onvifptz.Controller
	logger     *slog.Logger
}

func (a ptzAdapter) Capability(ctx context.Context) (omadafront.PTZCapability, error) {
	capability, err := a.controller.Capability(ctx)
	if err != nil {
		return omadafront.PTZCapability{}, err
	}
	return omadafront.PTZCapability{PanTilt: capability.PanTilt, Zoom: capability.Zoom, MaxPresets: capability.MaxPresets, Home: capability.Home}, nil
}

func (a ptzAdapter) Move(pan, tilt, zoom float64) { a.controller.Move(pan, tilt, zoom) }

func (a ptzAdapter) Stop() { a.controller.Stop() }

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

func (a ptzAdapter) GotoPreset(ctx context.Context, id int) error {
	if id < 1 {
		return onvifptz.ErrUnsupported
	}
	return a.logged("goto_preset", a.controller.GotoPreset(ctx, strconv.Itoa(id)))
}

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

func (a ptzAdapter) RemovePreset(ctx context.Context, id int) error {
	if id < 1 {
		return onvifptz.ErrUnsupported
	}
	return a.logged("remove_preset", a.controller.RemovePreset(ctx, strconv.Itoa(id)))
}

func (a ptzAdapter) logged(operation string, err error) error {
	if err != nil {
		a.logger.Warn("ptz command failed", "operation", operation, "failure", onvifptz.ErrorClass(err))
	} else {
		a.logger.Info("ptz command sent", "operation", operation)
	}
	return err
}
