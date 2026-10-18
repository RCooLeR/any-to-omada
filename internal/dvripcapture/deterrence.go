package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

var (
	// ErrDeterrenceUnsupported means the configured output is not explicitly advertised.
	ErrDeterrenceUnsupported = errors.New("native deterrence output unsupported")
	// ErrDeterrenceBusy prevents overlapping or unresolved alarm activations.
	ErrDeterrenceBusy = errors.New("native deterrence output busy")
	// ErrDeterrenceUnavailable means the controller is closed or cooling down after rejection.
	ErrDeterrenceUnavailable = errors.New("native deterrence output unavailable")
	// ErrDeterrenceStop means the device has not acknowledged deactivation.
	ErrDeterrenceStop = errors.New("native deterrence stop unconfirmed")
)

// DeterrenceConfig enables selected native alarm outputs for one zero-based
// channel. Alarm light can flash; it is distinct from steady illumination.
type DeterrenceConfig struct {
	Device      capture.Device
	Channel     int
	MaxDuration time.Duration
	Light       bool
	Sound       bool
}

// DeterrenceCapability describes the explicit CoaxialControlIO capability read.
// It does not establish physical actuation or an effective device-side timer.
type DeterrenceCapability struct{ Light, Sound bool }

// DeterrenceStatus records acknowledged commands, not measured physical state.
// Unconfirmed remains true after an uncertain start or an unacknowledged stop.
type DeterrenceStatus struct {
	Active      bool `json:"active"`
	Unconfirmed bool `json:"unconfirmed"`
	Light       bool `json:"light"`
	Sound       bool `json:"sound"`
}

// Deterrence serializes one source channel's alarm commands and owns a bounded
// stop watchdog. Stop cancels a pending Start before waiting for its I/O slot.
// Callers must Close it before discarding it, including on process shutdown.
type Deterrence struct {
	cfg     DeterrenceConfig
	session func(context.Context, func(lightingCall) error) error
	gate    chan struct{}
	wake    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	close   sync.Once
	// mu guards status, lifecycle and the pending request; no I/O holds it.
	mu           sync.Mutex
	status       DeterrenceStatus
	expires      time.Time
	blockedUntil time.Time
	activeCancel context.CancelFunc
	starting     bool
	closed       bool
	closeErr     error
}

// NewDeterrence validates the opt-in and starts a watchdog without contacting
// the camera. Native capability is checked before every activation.
func NewDeterrence(cfg DeterrenceConfig) (*Deterrence, error) {
	ip, err := netip.ParseAddr(cfg.Device.Host)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || cfg.Device.Username == "" || cfg.Device.Password == "" || cfg.Device.NativePort < 0 || cfg.Device.NativePort > 65535 {
		return nil, errors.New("native deterrence source is invalid")
	}
	if cfg.Channel < 0 || cfg.Channel > 65535 || (!cfg.Light && !cfg.Sound) || cfg.MaxDuration < time.Second || cfg.MaxDuration > 5*time.Second {
		return nil, errors.New("native deterrence channel, outputs or duration are invalid")
	}
	return newDeterrence(cfg, NewLighting(cfg.Device).session), nil
}

// newDeterrence binds a session implementation and launches the owned watchdog.
func newDeterrence(cfg DeterrenceConfig, session func(context.Context, func(lightingCall) error) error) *Deterrence {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Deterrence{cfg: cfg, session: session, gate: make(chan struct{}, 1), wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go c.watchdog()
	return c
}

// Capability reads native flags without activating anything. A failed or
// malformed read never produces a positive capability.
func (c *Deterrence) Capability(ctx context.Context) (caps DeterrenceCapability, result error) {
	if err := c.acquire(ctx); err != nil {
		return caps, err
	}
	defer c.release()
	c.mu.Lock()
	unavailable := c.closed || time.Now().Before(c.blockedUntil)
	c.mu.Unlock()
	if unavailable {
		return caps, ErrDeterrenceUnavailable
	}
	result = c.session(ctx, func(call lightingCall) error {
		var err error
		caps, err = deterrenceCaps(ctx, call, c.cfg.Channel)
		caps.Light = caps.Light && c.cfg.Light
		caps.Sound = caps.Sound && c.cfg.Sound
		return err
	})
	if result != nil {
		c.recordFailure(result)
		return DeterrenceCapability{}, deterrenceFailure(result)
	}
	return caps, nil
}

// Start activates only requested, configured and source-advertised outputs.
// Success means the native write was acknowledged. It never retries a start,
// and an uncertain write triggers a separate bounded stop attempt.
func (c *Deterrence) Start(ctx context.Context, light, sound bool) (time.Duration, error) {
	if (!light && !sound) || (light && !c.cfg.Light) || (sound && !c.cfg.Sound) {
		return 0, ErrDeterrenceUnsupported
	}
	request, cancel := context.WithCancel(ctx)
	defer cancel()
	c.mu.Lock()
	if c.closed || time.Now().Before(c.blockedUntil) {
		c.mu.Unlock()
		return 0, ErrDeterrenceUnavailable
	}
	if c.starting || c.status.Active || c.status.Unconfirmed {
		c.mu.Unlock()
		return 0, ErrDeterrenceBusy
	}
	c.starting, c.activeCancel = true, cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.starting, c.activeCancel = false, nil
		c.mu.Unlock()
	}()
	if err := c.acquire(request); err != nil {
		return 0, err
	}
	defer c.release()
	attempted := false
	err := c.session(request, func(call lightingCall) error {
		caps, err := deterrenceCaps(request, call, c.cfg.Channel)
		if err != nil {
			return err
		}
		if (light && !caps.Light) || (sound && !caps.Sound) {
			return ErrDeterrenceUnsupported
		}
		if err := request.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		c.status = DeterrenceStatus{Light: light, Sound: sound, Unconfirmed: true}
		c.expires = time.Now().Add(c.cfg.MaxDuration)
		c.mu.Unlock()
		c.notify()
		attempted = true
		_, err = call(request, "CoaxialControlIO.control", deterrenceCommand(c.cfg.Channel, light, sound, 1))
		return err
	})
	if err == nil {
		err = request.Err()
	}
	if err != nil {
		c.recordFailure(err)
		if attempted {
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cleanupCancel()
			err = errors.Join(deterrenceFailure(err), c.stopHeld(cleanup))
		}
		return 0, deterrenceFailure(err)
	}
	c.mu.Lock()
	c.status.Active, c.status.Unconfirmed = true, false
	c.mu.Unlock()
	c.notify()
	return c.cfg.MaxDuration, nil
}

// Stop cancels pending activation, then deactivates the outputs this controller
// may have started. It bypasses capability and authentication cooldown checks.
func (c *Deterrence) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.activeCancel != nil {
		c.activeCancel()
	}
	c.mu.Unlock()
	if err := c.acquire(ctx); err != nil {
		return errors.Join(ErrDeterrenceStop, err)
	}
	defer c.release()
	return c.stopHeld(ctx)
}

// stopHeld sends one deactivation while the caller owns the native I/O slot.
func (c *Deterrence) stopHeld(ctx context.Context) error {
	c.mu.Lock()
	state := c.status
	c.expires = time.Time{}
	c.mu.Unlock()
	if !state.Active && !state.Unconfirmed {
		return nil
	}
	err := c.session(ctx, func(call lightingCall) error {
		_, err := call(ctx, "CoaxialControlIO.control", deterrenceCommand(c.cfg.Channel, state.Light, state.Sound, 2))
		return err
	})
	c.mu.Lock()
	if err == nil {
		c.status = DeterrenceStatus{}
	} else {
		c.status.Unconfirmed = true
	}
	c.mu.Unlock()
	if err != nil {
		c.recordFailure(err)
		return errors.Join(ErrDeterrenceStop, deterrenceFailure(err))
	}
	return nil
}

// Status returns a copy of command state; getStatus is not implemented by some
// cameras that explicitly advertise both alarm outputs.
func (c *Deterrence) Status() DeterrenceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Close cancels new work, joins the watchdog, and attempts a final acknowledged
// stop. Failed cleanup remains visible in Status and the returned error.
func (c *Deterrence) Close() error {
	c.close.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.closeErr = c.Stop(ctx)
		<-c.done
	})
	return c.closeErr
}

// watchdog stops once at expiry and leaves failures unresolved for the caller.
func (c *Deterrence) watchdog() {
	defer close(c.done)
	for {
		c.mu.Lock()
		expires := c.expires
		c.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !expires.IsZero() {
			timer = time.NewTimer(time.Until(expires))
			expired = timer.C
		}
		select {
		case <-c.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-c.wake:
		case <-expired:
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			// Status retains a failed stop so the failure is not hidden by expiry.
			_ = c.stopExpired(ctx, expires)
			cancel()
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// stopExpired only stops the activation whose deadline fired; an old timer
// must never cancel a later request after an explicit Stop and another Start.
func (c *Deterrence) stopExpired(ctx context.Context, expires time.Time) error {
	c.mu.Lock()
	current := !c.expires.IsZero() && c.expires.Equal(expires) && !time.Now().Before(c.expires)
	if current && c.activeCancel != nil {
		c.activeCancel()
	}
	c.mu.Unlock()
	if !current {
		return nil
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	c.mu.Lock()
	current = !c.expires.IsZero() && c.expires.Equal(expires) && !time.Now().Before(c.expires)
	c.mu.Unlock()
	if !current {
		return nil
	}
	return c.stopHeld(ctx)
}

// acquire reserves the single I/O slot without holding the state mutex.
func (c *Deterrence) acquire(ctx context.Context) error {
	select {
	case c.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release makes the I/O slot available after one complete native operation.
func (c *Deterrence) release() { <-c.gate }

// notify wakes the watchdog when an acknowledged activation sets a deadline.
func (c *Deterrence) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// recordFailure prevents repeated authentication or authority rejection writes.
func (c *Deterrence) recordFailure(err error) {
	var native *LightingError
	if errors.Is(err, capture.ErrAuthentication) || (errors.As(err, &native) && native.DeviceCode != nil && *native.DeviceCode == 285278249) {
		c.mu.Lock()
		c.blockedUntil = time.Now().Add(time.Minute)
		c.mu.Unlock()
	}
}

// deterrenceCaps requires explicit numeric or string one values. Merely
// returning WhiteLight/Speaker status fields does not advertise hardware.
func deterrenceCaps(ctx context.Context, call lightingCall, channel int) (DeterrenceCapability, error) {
	answer, err := call(ctx, "CoaxialControlIO.getCaps", map[string]any{"channel": channel})
	if err != nil {
		return DeterrenceCapability{}, err
	}
	params, _ := answer["params"].(map[string]any)
	caps, ok := params["caps"].(map[string]any)
	if !ok {
		return DeterrenceCapability{}, ErrDeterrenceUnsupported
	}
	one := func(value any) bool { return value == json.Number("1") || value == "1" }
	return DeterrenceCapability{Light: one(caps["SupportControlLight"]), Sound: one(caps["SupportControlSpeaker"])}, nil
}

// deterrenceCommand encodes independently selected alarm light and speaker.
// IO=2 is the observed client contract for deactivation; it is never guessed
// by trying alternate values after a rejected or uncertain command.
func deterrenceCommand(channel int, light, sound bool, io int) map[string]any {
	info := []any{}
	if light {
		info = append(info, map[string]any{"Type": 1, "IO": io, "TriggerMode": 2})
	}
	if sound {
		info = append(info, map[string]any{"Type": 2, "IO": io, "TriggerMode": 2})
	}
	return map[string]any{"channel": channel, "info": info}
}

// deterrenceFailure preserves fixed classifications while suppressing native
// peer strings. Existing session diagnostics already retain numeric codes only.
func deterrenceFailure(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrLightingUnsupported) {
		return errors.Join(ErrDeterrenceUnsupported, err)
	}
	return err
}
