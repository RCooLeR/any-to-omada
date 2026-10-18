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
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	refresh chan struct{}
	ready   chan struct{}
	start   sync.Once
	// mu guards lifecycle, failure state and the passive settings snapshot.
	// Device I/O and snapshot publication share the physical source gate.
	mu                     sync.Mutex
	restorationUnconfirmed bool
	closing                bool
	active                 sync.WaitGroup
	snapshot               omadafront.IlluminationSettings
	snapshotAt             time.Time
}

const (
	illuminationRefreshInterval  = 10 * time.Second
	illuminationSnapshotLifetime = 30 * time.Second
	illuminationReadTimeout      = 4 * time.Second
)

var errIlluminationSnapshotUnavailable = errors.New("illumination source snapshot unavailable")

// newCameraIllumination owns an idle refresh worker. Start releases it after
// startup validation; cancellation also releases a worker that was never started.
func newCameraIllumination(parent context.Context, cfg *config.WhiteLight, channel int, light illuminationControl, gate *sourceControlGate, logger *slog.Logger) *cameraIllumination {
	ctx, cancel := context.WithCancel(parent)
	c := &cameraIllumination{cfg: cfg, channel: channel, light: light, gate: gate, logger: logger,
		ctx: ctx, cancel: cancel, done: make(chan struct{}), refresh: make(chan struct{}, 1), ready: make(chan struct{})}
	go c.refreshLoop()
	return c
}

// Start begins asynchronous source refresh after local listener validation.
func (c *cameraIllumination) Start() { c.start.Do(func() { close(c.ready) }) }

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

// Settings returns only a recent validated snapshot. It never contacts or waits
// for a source, so recorder enrollment and callback heartbeats cannot be held
// behind source discovery. Cold, expired and failed snapshots remain unknown.
func (c *cameraIllumination) Settings(ctx context.Context) (omadafront.IlluminationSettings, error) {
	if err := ctx.Err(); err != nil {
		return omadafront.IlluminationSettings{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.ctx.Err() != nil || c.snapshotAt.IsZero() || time.Since(c.snapshotAt) >= illuminationSnapshotLifetime {
		return omadafront.IlluminationSettings{}, errIlluminationSnapshotUnavailable
	}
	return c.snapshot, nil
}

// sourceSettings preserves an unmapped policy as an omitted mode rather than
// inventing OFF, and rejects malformed source brightness or lamp modes.
func (c *cameraIllumination) sourceSettings(current dvripcapture.LightingModeSettings) (omadafront.IlluminationSettings, error) {
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
	if (current.WhiteMode != "Manual" && current.WhiteMode != "Auto") || current.Brightness < 0 || current.Brightness > 100 {
		return omadafront.IlluminationSettings{}, errControlUnsupported
	}
	return omadafront.IlluminationSettings{Mode: mode, Brightness: current.Brightness, AutomaticBrightness: current.WhiteMode == "Auto"}, nil
}

// refreshLoop owns initial, periodic and post-write snapshot reads. At most one
// refresh exists, and no caller waits for it to finish.
func (c *cameraIllumination) refreshLoop() {
	defer close(c.done)
	select {
	case <-c.ctx.Done():
		return
	case <-c.ready:
	}
	ticker := time.NewTicker(illuminationRefreshInterval)
	defer ticker.Stop()
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.refreshSnapshot()
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.refresh:
		}
	}
}

// refreshSnapshot publishes before releasing source admission. A later Set
// therefore invalidates this result after acquiring the same gate, never before.
func (c *cameraIllumination) refreshSnapshot() {
	if err := c.acquire(); err != nil {
		if !errors.Is(err, errSourceControlBusy) {
			c.invalidateSnapshot()
		}
		return
	}
	defer func() { <-c.gate.busy }()
	ctx, cancel := context.WithTimeout(c.ctx, illuminationReadTimeout)
	defer cancel()
	current, err := c.light.ModeSettings(ctx, c.channel, c.cfg.Profile)
	var snapshot omadafront.IlluminationSettings
	if err == nil {
		snapshot, err = c.sourceSettings(current)
	}
	c.failure(err)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil || c.closing || c.ctx.Err() != nil {
		c.snapshotAt = time.Time{}
		return
	}
	c.snapshot, c.snapshotAt = snapshot, time.Now()
}

// invalidateSnapshot makes uncertain or superseded source settings unavailable.
func (c *cameraIllumination) invalidateSnapshot() {
	c.mu.Lock()
	c.snapshotAt = time.Time{}
	c.mu.Unlock()
}

// requestRefresh coalesces writes into one immediate read after source release.
func (c *cameraIllumination) requestRefresh() {
	select {
	case c.refresh <- struct{}{}:
	default:
	}
}

// Set validates the entire requested policy/brightness combination before
// sending one source transaction. Brightness always targets the white bank.
func (c *cameraIllumination) Set(ctx context.Context, change omadafront.IlluminationChange) error {
	if !c.begin() {
		return errControlUnsupported
	}
	defer c.active.Done()
	request, cancel := context.WithCancel(ctx)
	stopCancellation := context.AfterFunc(c.ctx, cancel)
	defer func() { stopCancellation(); cancel() }()
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
	defer func() {
		<-c.gate.busy
		c.requestRefresh()
	}()
	c.invalidateSnapshot()
	err := c.light.ApplyMode(request, c.channel, c.cfg.Profile, native)
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
	if c.closing || c.ctx.Err() != nil {
		return false
	}
	c.active.Add(1)
	return true
}

// Close cancels refresh and write contexts, then joins the worker and independent
// source rollback before this camera's controls are discarded.
func (c *cameraIllumination) Close() {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.cancel()
	<-c.done
	c.active.Wait()
}
