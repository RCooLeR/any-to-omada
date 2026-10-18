package app

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
)

// illuminationControl reads and intentionally persists verified source lamp
// fields. Failed partial writes must attempt restoration and report uncertainty.
type illuminationControl interface {
	ModeSettings(context.Context, int, int) (dvripcapture.LightingModeSettings, error)
	ApplyMode(context.Context, int, int, dvripcapture.LightingChange) error
}

// cameraIllumination translates native recorder policy names into source lamp
// settings for one fixed active profile. It shares source control admission.
type cameraIllumination struct {
	cfg     *config.WhiteLight
	channel int
	light   illuminationControl
	gate    *sourceControlGate
	logger  *slog.Logger
	// mu guards failure state only; device I/O uses the shared source gate.
	mu                     sync.Mutex
	restorationUnconfirmed bool
	closing                bool
	active                 sync.WaitGroup
}

// illuminationStatus preserves uncertain persistent writes until a later
// intentional write succeeds; a successful read alone does not imply recovery.
type illuminationStatus struct {
	RestorationUnconfirmed bool `json:"restoration_unconfirmed"`
}

// Status returns whether a failed persistent write still needs reconciliation.
func (c *cameraIllumination) Status() illuminationStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return illuminationStatus{RestorationUnconfirmed: c.restorationUnconfirmed}
}

// Capabilities returns the modes explicitly selected for this verified source.
func (c *cameraIllumination) Capabilities() omadafront.IlluminationCapability {
	return omadafront.IlluminationCapability{Modes: slices.Clone(c.cfg.RecorderModes), Brightness: true, AutomaticBrightness: true}
}

// Settings preserves unknown native source policies as an omitted mode rather
// than falsely reporting OFF or changing a smart lighting policy on read.
func (c *cameraIllumination) Settings(ctx context.Context) (omadafront.IlluminationSettings, error) {
	if !c.begin() {
		return omadafront.IlluminationSettings{}, errControlUnsupported
	}
	defer c.active.Done()
	if err := c.acquire(); err != nil {
		return omadafront.IlluminationSettings{}, err
	}
	defer func() { <-c.gate.busy }()
	current, err := c.light.ModeSettings(ctx, c.channel, c.cfg.Profile)
	if err != nil {
		c.failure(err)
		return omadafront.IlluminationSettings{}, err
	}
	mode := ""
	switch {
	case current.Scheme == "WhiteMode" && current.WhiteMode == "Manual":
		mode = "white_led_always_on"
	case current.Scheme == "WhiteMode" && current.WhiteMode == "Auto":
		mode = "auto_color"
	case current.Scheme == "InfraredMode" && current.InfraredMode == "Manual":
		mode = "ir_always_on"
	case current.Scheme == "InfraredMode" && current.InfraredMode == "Auto":
		mode = "auto_ir"
	}
	if !slices.Contains(c.cfg.RecorderModes, mode) {
		mode = ""
	}
	if current.WhiteMode != "Manual" && current.WhiteMode != "Auto" {
		return omadafront.IlluminationSettings{}, errControlUnsupported
	}
	return omadafront.IlluminationSettings{Mode: mode, Brightness: current.Brightness, AutomaticBrightness: current.WhiteMode == "Auto"}, nil
}

// Set validates the entire requested policy/brightness combination before
// sending one source transaction. Brightness always targets the white bank.
func (c *cameraIllumination) Set(ctx context.Context, change omadafront.IlluminationChange) error {
	if !c.begin() {
		return errControlUnsupported
	}
	defer c.active.Done()
	if change.Mode != "" && !slices.Contains(c.cfg.RecorderModes, change.Mode) {
		return errControlUnsupported
	}
	native := dvripcapture.LightingChange{Brightness: change.Brightness}
	switch change.Mode {
	case "white_led_always_on":
		native.Scheme, native.WhiteMode = "WhiteMode", "Manual"
	case "auto_color":
		native.Scheme, native.WhiteMode = "WhiteMode", "Auto"
	case "auto_ir":
		native.Scheme, native.InfraredMode = "InfraredMode", "Auto"
	case "ir_always_on":
		native.Scheme, native.InfraredMode = "InfraredMode", "Manual"
	}
	if change.AutomaticBrightness != nil {
		mode := "Manual"
		if *change.AutomaticBrightness {
			mode = "Auto"
		}
		if native.WhiteMode != "" && native.WhiteMode != mode {
			return errControlUnsupported
		}
		native.WhiteMode = mode
	}
	if err := c.acquire(); err != nil {
		return err
	}
	defer func() { <-c.gate.busy }()
	err := c.light.ApplyMode(ctx, c.channel, c.cfg.Profile, native)
	c.failure(err)
	c.mu.Lock()
	if err == nil {
		c.restorationUnconfirmed = false
	} else if errors.Is(err, dvripcapture.ErrLightingRestore) {
		c.restorationUnconfirmed = true
	}
	c.mu.Unlock()
	if errors.Is(err, dvripcapture.ErrLightingRestore) && c.logger != nil {
		c.logger.Warn("illumination restoration unconfirmed")
	}
	return err
}

// acquire prevents simultaneous source configuration writes and respects the
// shared authentication cooldown without holding a mutex during device I/O.
func (c *cameraIllumination) acquire() error {
	select {
	case c.gate.busy <- struct{}{}:
	default:
		return errSourceControlBusy
	}
	if time.Now().Before(c.gate.blockedUntil) {
		<-c.gate.busy
		return capture.ErrAuthentication
	}
	return nil
}

// failure shares rejected credentials across this source's output clients.
// The caller holds source admission while changing the cooldown.
func (c *cameraIllumination) failure(err error) {
	if errors.Is(err, capture.ErrAuthentication) {
		c.gate.blockedUntil = time.Now().Add(time.Minute)
	}
}

// begin closes admission before the shutdown wait can observe an empty group.
func (c *cameraIllumination) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return false
	}
	c.active.Add(1)
	return true
}

// Close prevents new operations and joins independent source rollback after
// the HTTP server has cancelled the originating request.
func (c *cameraIllumination) Close() {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.active.Wait()
}
