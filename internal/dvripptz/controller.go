// Package dvripptz controls explicitly selected native Dahua/Imou pan/tilt
// channels. It supports bounded manual movement only, without zoom or presets.
package dvripptz

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
)

// Config selects a verified physical channel and bounds unacknowledged movement.
type Config struct {
	Device  capture.Device
	Channel int
	MaxMove time.Duration
	Logger  *slog.Logger
}

// nativeMove preserves the exact arguments needed to stop a movement, including
// a start whose response was lost. The shipped camera UI uses speeds one to eight.
type nativeMove struct {
	Code    string `json:"code"`
	Arg1    int    `json:"arg1"`
	Arg2    int    `json:"arg2"`
	Arg3    int    `json:"arg3"`
	Arg4    int    `json:"arg4"`
	Channel int    `json:"channel"`
}

// command is replaced atomically; a later Stop invalidates discovery in progress.
type command struct {
	move     *nativeMove
	sequence uint64
}

// Controller serializes movements and stops through isolated native sessions.
// mu protects queue, status, discovery cache and authentication cooldown; network
// calls occur outside mu. The worker alone owns the last uncertain movement.
type Controller struct {
	config                        Config
	session                       func(context.Context, capture.Device, func(dvripcapture.ControlCall) error) error
	ctx                           context.Context
	cancel                        context.CancelFunc
	done                          chan struct{}
	wake                          chan struct{}
	sessionGate                   chan struct{}
	mu                            sync.Mutex
	pending                       *command
	sequence                      uint64
	activeCancel                  context.CancelFunc
	status                        onvifptz.Status
	capability                    onvifptz.Capability
	capabilityUntil, blockedUntil time.Time
	active                        *nativeMove
	rpcSequence                   uint32
}

// New validates configuration and starts an idle worker without camera traffic.
func New(config Config) (*Controller, error) {
	ip, err := netip.ParseAddr(config.Device.Host)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || config.Device.Username == "" || config.Device.Password == "" || config.Device.NativePort < 0 || config.Device.NativePort > 65535 || config.Channel < 0 || config.Channel > 255 {
		return nil, errors.New("native ptz source or channel is invalid")
	}
	if config.MaxMove == 0 {
		config.MaxMove = 2 * time.Second
	}
	if config.MaxMove < time.Second || config.MaxMove > 60*time.Second {
		return nil, errors.New("native ptz maximum move must be one to 60 seconds")
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{config: config, session: dvripcapture.ControlSession, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), sessionGate: make(chan struct{}, 1)}
	go c.run()
	return c, nil
}

// Close stops admission and waits for bounded cleanup of any uncertain movement.
func (c *Controller) Close() { c.cancel(); <-c.done }

// Status returns counters without asserting a stop unless the camera acknowledged it.
func (c *Controller) Status() onvifptz.Status { c.mu.Lock(); defer c.mu.Unlock(); return c.status }

// Capability reads native protocol caps. Both explicit motor axes and valid speed
// bounds are required; generic ONVIF spaces on fixed cameras are not consulted.
func (c *Controller) Capability(ctx context.Context) (onvifptz.Capability, error) {
	select {
	case c.sessionGate <- struct{}{}:
		defer func() { <-c.sessionGate }()
	case <-ctx.Done():
		return onvifptz.Capability{}, onvifptz.ErrUnavailable
	case <-c.ctx.Done():
		return onvifptz.Capability{}, onvifptz.ErrUnavailable
	}
	if c.ctx.Err() != nil {
		return onvifptz.Capability{}, onvifptz.ErrUnavailable
	}
	c.mu.Lock()
	// A capability login must not consume or suppress the authentication
	// attempts needed to stop a previously sent, uncertain movement.
	if c.status.Moving {
		capability := c.capability
		c.mu.Unlock()
		return capability, nil
	}
	if time.Now().Before(c.blockedUntil) {
		c.mu.Unlock()
		return onvifptz.Capability{}, onvifptz.ErrAuthentication
	}
	if time.Now().Before(c.capabilityUntil) {
		capability := c.capability
		c.mu.Unlock()
		return capability, nil
	}
	c.mu.Unlock()
	var capability onvifptz.Capability
	err := c.session(ctx, c.config.Device, func(call dvripcapture.ControlCall) error {
		object, err := factory(ctx, call, c.config.Channel)
		if err != nil {
			return err
		}
		capability, err = readCapability(ctx, call, object)
		return err
	})
	if err != nil {
		return onvifptz.Capability{}, c.failure("capability", err)
	}
	c.mu.Lock()
	c.capability, c.capabilityUntil = capability, time.Now().Add(10*time.Minute)
	c.mu.Unlock()
	return capability, nil
}

// Move queues firmware-supported directions. Unsupported zoom never causes a
// physical command; a zero vector has the same semantics as Stop.
func (c *Controller) Move(pan, tilt, zoom float64) {
	if zoom != 0 || math.IsNaN(zoom) {
		c.Stop()
		return
	}
	c.submit(direction(pan, tilt, c.config.Channel))
}

// Stop cancels pending discovery and requests acknowledged stop of the last move.
func (c *Controller) Stop() { c.submit(nil) }

// submit keeps only the latest request and interrupts an in-flight start so its
// cleanup can send Stop on a fresh session if stream alignment became uncertain.
func (c *Controller) submit(move *nativeMove) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.sequence++
	c.pending = &command{move: move, sequence: c.sequence}
	cancel := c.activeCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// run never overlaps movement sessions. Failed Stop leaves Moving true and
// prevents a replacement movement until a later cleanup acknowledges the stop.
func (c *Controller) run() {
	defer close(c.done)
	defer func() {
		c.sessionGate <- struct{}{}
		defer func() { <-c.sessionGate }()
		c.recoverStop()
	}()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.wake:
		}
		select {
		case c.sessionGate <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		c.applyPending()
		<-c.sessionGate
	}
}

// applyPending holds the source-session gate through discovery, movement and
// cleanup, preventing concurrent discovery logins from interfering with Stop.
func (c *Controller) applyPending() {
	c.mu.Lock()
	cmd := c.pending
	c.pending = nil
	c.mu.Unlock()
	if cmd == nil {
		return
	}
	if c.active != nil {
		c.recoverStop()
	}
	if c.active != nil || cmd.move == nil {
		return
	}
	c.execute(*cmd)
}

// execute verifies native motor caps before starting. The watchdog starts before
// the start RPC, and cleanup runs even if its response is lost or cancelled.
func (c *Controller) execute(cmd command) {
	c.mu.Lock()
	if time.Now().Before(c.blockedUntil) {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(c.ctx)
	c.activeCancel = cancel
	c.mu.Unlock()
	defer func() { cancel(); c.mu.Lock(); c.activeCancel = nil; c.mu.Unlock() }()
	err := c.session(ctx, c.config.Device, func(call dvripcapture.ControlCall) error {
		object, err := factory(ctx, call, c.config.Channel)
		if err != nil {
			return err
		}
		capability, err := readCapability(ctx, call, object)
		if err != nil {
			return err
		}
		if !capability.PanTilt {
			return onvifptz.ErrUnsupported
		}
		c.mu.Lock()
		c.capability, c.capabilityUntil = capability, time.Now().Add(10*time.Minute)
		stale := cmd.sequence != c.sequence || ctx.Err() != nil
		c.mu.Unlock()
		if stale {
			return nil
		}
		c.active = cmd.move
		c.mu.Lock()
		c.status.Moving = true
		c.mu.Unlock()
		deadline := time.Now().Add(c.config.MaxMove)
		startCtx, startCancel := context.WithDeadline(ctx, deadline)
		_, err = call(startCtx, c.request("ptz.start", object, *cmd.move))
		startCancel()
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.status.Moves++
		c.mu.Unlock()
		timer := time.NewTimer(max(0, time.Until(deadline)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			c.mu.Lock()
			c.status.WatchdogStops++
			c.mu.Unlock()
		}
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cleanupCancel()
		if _, err := call(cleanup, c.request("ptz.stop", object, *cmd.move)); err != nil {
			return err
		}
		c.stopped()
		return nil
	})
	if err != nil {
		c.failure("move", err)
	}
	if c.active != nil {
		c.recoverStop()
	}
}

// recoverStop reconnects only to stop an uncertain movement, never to repeat its
// start. Authentication rejection suppresses subsequent attempts for 15 minutes.
func (c *Controller) recoverStop() {
	for attempt := 0; c.active != nil && attempt < 3; attempt++ {
		c.mu.Lock()
		blocked := time.Now().Before(c.blockedUntil)
		c.mu.Unlock()
		if blocked {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		err := c.session(ctx, c.config.Device, func(call dvripcapture.ControlCall) error {
			object, err := factory(ctx, call, c.config.Channel)
			if err != nil {
				return err
			}
			_, err = call(ctx, c.request("ptz.stop", object, *c.active))
			if err == nil {
				c.stopped()
			}
			return err
		})
		cancel()
		if err != nil {
			c.failure("stop", err)
		}
	}
}

// stopped clears uncertainty only after a positive device response.
func (c *Controller) stopped() {
	c.active = nil
	c.mu.Lock()
	c.status.Moving = false
	c.status.Stops++
	c.mu.Unlock()
}

// request supplies the factory handle and increasing sequence used by shipped
// Dahua UI code. Stop repeats precisely the preceding start's direction/speeds.
func (c *Controller) request(method string, object uint32, move nativeMove) dvripcapture.ControlRequest {
	c.rpcSequence++
	if c.rpcSequence == 0 {
		c.rpcSequence++
	}
	return dvripcapture.ControlRequest{Method: method, Object: object, Sequence: c.rpcSequence, SessionSequence: true, Params: move}
}

// failure maps native response bodies to fixed labels and remembers auth rejection.
func (c *Controller) failure(operation string, err error) error {
	result := onvifptz.ErrUnavailable
	if errors.Is(err, capture.ErrAuthentication) || errors.Is(err, onvifptz.ErrAuthentication) {
		result = onvifptz.ErrAuthentication
	}
	if errors.Is(err, onvifptz.ErrUnsupported) {
		result = onvifptz.ErrUnsupported
	}
	c.mu.Lock()
	c.status.Failures++
	c.status.LastFailure = operation + ":" + onvifptz.ErrorClass(result)
	if result == onvifptz.ErrAuthentication {
		c.blockedUntil = time.Now().Add(15 * time.Minute)
	}
	c.mu.Unlock()
	c.config.Logger.Warn("native ptz operation failed", "operation", operation, "failure", onvifptz.ErrorClass(result))
	return result
}

// factory obtains a session-scoped handle without moving or configuring the lens.
func factory(ctx context.Context, call dvripcapture.ControlCall, channel int) (uint32, error) {
	answer, err := call(ctx, dvripcapture.ControlRequest{Method: "ptz.factory.instance", Params: map[string]int{"channel": channel}})
	if err != nil {
		return 0, err
	}
	number, ok := answer["result"].(json.Number)
	if !ok {
		return 0, onvifptz.ErrUnavailable
	}
	object, err := strconv.ParseUint(string(number), 10, 32)
	if err != nil || object == 0 {
		return 0, onvifptz.ErrUnavailable
	}
	return uint32(object), nil
}

// readCapability requires affirmative native axes and sane advertised speed ranges.
func readCapability(ctx context.Context, call dvripcapture.ControlCall, object uint32) (onvifptz.Capability, error) {
	answer, err := call(ctx, dvripcapture.ControlRequest{Method: "ptz.getCurrentProtocolCaps", Object: object})
	if err != nil {
		return onvifptz.Capability{}, err
	}
	params, _ := answer["params"].(map[string]any)
	caps, _ := params["caps"].(map[string]any)
	validRange := func(minKey, maxKey string) bool {
		minimum, ok := caps[minKey].(json.Number)
		if !ok {
			return false
		}
		maximum, ok := caps[maxKey].(json.Number)
		if !ok {
			return false
		}
		low, e1 := minimum.Int64()
		high, e2 := maximum.Int64()
		return e1 == nil && e2 == nil && low <= 1 && low >= 0 && high >= 8 && high <= 65535
	}
	return onvifptz.Capability{PanTilt: caps["Pan"] == true && caps["Tile"] == true && validRange("PanSpeedMin", "PanSpeedMax") && validRange("TileSpeedMin", "TileSpeedMax")}, nil
}

// direction quantizes normalized velocity to the camera UI's eight directions
// and bounded one-to-eight speed steps; +pan means right and +tilt means up.
func direction(pan, tilt float64, channel int) *nativeMove {
	if math.IsNaN(pan) || math.IsNaN(tilt) || math.IsInf(pan, 0) || math.IsInf(tilt, 0) {
		return nil
	}
	pan = max(-1, min(1, pan))
	tilt = max(-1, min(1, tilt))
	if pan == 0 && tilt == 0 {
		return nil
	}
	code := ""
	if pan < 0 {
		code = "Left"
	} else if pan > 0 {
		code = "Right"
	}
	if tilt < 0 {
		code += "Down"
	} else if tilt > 0 {
		code += "Up"
	}
	speed := max(1, min(8, int(math.Ceil(max(math.Abs(pan), math.Abs(tilt))*8))))
	move := &nativeMove{Code: code, Arg1: speed, Channel: channel}
	if pan != 0 && tilt != 0 {
		move.Arg2 = speed
	}
	return move
}

// Presets is unsupported: the native adapter exposes manual pan/tilt only.
func (c *Controller) Presets(context.Context) ([]onvifptz.Preset, error) {
	return nil, onvifptz.ErrUnsupported
}

// GotoPreset never sends native preset commands.
func (c *Controller) GotoPreset(context.Context, string) error { return onvifptz.ErrUnsupported }

// SetPreset never changes native presets.
func (c *Controller) SetPreset(context.Context, string, string) (string, error) {
	return "", onvifptz.ErrUnsupported
}

// RemovePreset never changes native presets.
func (c *Controller) RemovePreset(context.Context, string) error { return onvifptz.ErrUnsupported }
