package onvifptz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config selects one lens of a source camera. Credentials are the source
// account already used for media and events; they are kept only in memory.
type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string
	ProfileToken string
	// MaxMove bounds one movement that receives no stop, including preset
	// recall and absolute zoom. The local watchdog always uses this bound. The
	// camera-side ContinuousMove timeout is also set when the camera allows
	// it. Preset and absolute moves have no camera-side timeout. Default 10 s.
	MaxMove time.Duration
	Logger  *slog.Logger
}

// Capability is what the camera's ONVIF PTZ node offers for this lens.
type Capability struct {
	PanTilt        bool
	Zoom           bool
	ContinuousZoom bool
	MaxPresets     int
	Home           bool
}

// Preset is one stored camera position.
type Preset struct{ Token, Name string }

// Status holds bounded counters with fixed failure labels only.
type Status struct {
	// Moving includes an uncertain movement after a failed Stop; it becomes
	// false only after an acknowledged Stop, not merely an elapsed timer.
	Moving        bool   `json:"moving"`
	Moves         uint64 `json:"moves"`
	Stops         uint64 `json:"stops"`
	WatchdogStops uint64 `json:"watchdog_stops"`
	Failures      uint64 `json:"failures"`
	LastFailure   string `json:"last_failure,omitempty"`
}

type lensProfile struct {
	ptzPath, configuration            string
	panSpace, zoomSpace, absoluteZoom string
	timeout                           time.Duration
	capability                        Capability
}

type command struct {
	stop            bool
	pan, tilt, zoom float64
	preset          string
	sequence        uint64
	// A synchronous preset caller owns this command until completion or
	// cancellation; asynchronous Move and Stop use the controller context.
	ctx    context.Context
	result chan error
}

// Controller owns one movement worker. Move and Stop never block on the
// network: the latest command wins and the worker sends it, so a recorder
// connection is never held by a slow camera.
type Controller struct {
	soap         *soapClient
	profileToken string
	maxMove      time.Duration
	logger       *slog.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	wake         chan struct{}
	gate         chan struct{}
	now          func() time.Time
	// mu guards the pending command, cached profile and status; network I/O
	// never holds it.
	mu           sync.Mutex
	pending      *command
	profile      *lensProfile
	expires      time.Time
	retryAfter   time.Time
	status       Status
	sequence     uint64
	activeCancel context.CancelFunc
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// New validates the configuration and starts the movement worker without
// contacting the camera; discovery happens on first use.
func New(cfg Config) (*Controller, error) {
	if ip, err := netip.ParseAddr(cfg.Host); err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, errors.New("ptz host must be an IPv4 address")
	}
	if cfg.Port < 1 || cfg.Port > 65535 || cfg.Username == "" || cfg.Password == "" || !headerText(cfg.Username) || !tokenPattern.MatchString(cfg.ProfileToken) {
		return nil, errors.New("ptz port, account or profile token is invalid")
	}
	if cfg.MaxMove == 0 {
		cfg.MaxMove = 10 * time.Second
	}
	if cfg.MaxMove < time.Second || cfg.MaxMove > 60*time.Second {
		return nil, errors.New("ptz maximum move must be between one and 60 seconds")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{soap: newSOAP(cfg.Host, cfg.Port, cfg.Username, cfg.Password), profileToken: cfg.ProfileToken, maxMove: cfg.MaxMove,
		logger: cfg.Logger, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), gate: make(chan struct{}, 1), now: time.Now}
	go c.run()
	return c, nil
}

// Close ends the worker; a movement in progress receives a final stop.
func (c *Controller) Close() {
	c.cancel()
	<-c.done
	c.soap.http.CloseIdleConnections()
}

// Status returns a detached snapshot.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Capability performs a bounded, cached discovery read; it never moves.
func (c *Controller) Capability(ctx context.Context) (Capability, error) {
	p, err := c.lens(ctx)
	if err != nil {
		return Capability{}, err
	}
	return p.capability, nil
}

// Move queues a continuous movement with velocities in -1..1.
func (c *Controller) Move(pan, tilt, zoom float64) {
	clamp := func(v float64) float64 {
		if math.IsNaN(v) {
			return 0
		}
		return math.Max(-1, math.Min(1, v))
	}
	c.submit(command{pan: clamp(pan), tilt: clamp(tilt), zoom: clamp(zoom)})
}

// Stop queues a stop of every axis.
func (c *Controller) Stop() { c.submit(command{stop: true}) }

func (c *Controller) submit(cmd command) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		cmd.complete(ErrUnavailable)
		return
	}
	c.sequence++
	cmd.sequence = c.sequence
	if c.pending != nil {
		c.pending.complete(ErrUnavailable)
	}
	c.pending = &cmd
	cancel := c.activeCancel
	c.mu.Unlock()
	// A Stop received during discovery must prevent the stale Move from
	// starting later. An already sent request remains potentially applied.
	if cancel != nil {
		cancel()
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (cmd *command) complete(err error) {
	if cmd.result != nil {
		cmd.result <- err
	}
}

// commandContext cancels network work when a newer command supersedes it.
// Every caller releases the context before the worker accepts another command.
func (c *Controller) commandContext(cmd *command, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	stopCaller := func() bool { return false }
	if cmd.ctx != nil {
		stopCaller = context.AfterFunc(cmd.ctx, cancel)
	}
	c.mu.Lock()
	if cmd.sequence != c.sequence || c.ctx.Err() != nil || (cmd.ctx != nil && cmd.ctx.Err() != nil) {
		c.mu.Unlock()
		stopCaller()
		cancel()
		return nil, nil, ErrUnavailable
	}
	c.activeCancel = cancel
	c.mu.Unlock()
	return ctx, func() {
		stopCaller()
		cancel()
		c.mu.Lock()
		c.activeCancel = nil
		c.mu.Unlock()
	}, nil
}

func (c *Controller) run() {
	defer close(c.done)
	defer func() {
		c.mu.Lock()
		if c.pending != nil {
			c.pending.complete(ErrUnavailable)
			c.pending = nil
		}
		c.mu.Unlock()
	}()
	watchdog := time.NewTimer(time.Hour)
	watchdog.Stop()
	defer watchdog.Stop()
	moving := false
	var deadline time.Time
	setMoving := func(value bool) {
		moving = value
		c.mu.Lock()
		c.status.Moving = value
		c.mu.Unlock()
	}
	stopMovement := func(reason string) {
		if err := c.stop(reason); err != nil {
			// A rejected or lost Stop does not establish that motion ended.
			// Retain the uncertain state and retry while the worker is alive.
			retry := 5 * time.Second
			if errors.Is(err, ErrAuthentication) {
				retry = 30 * time.Second
			}
			deadline = c.now().Add(retry)
			watchdog.Reset(retry)
			return
		}
		setMoving(false)
		deadline = time.Time{}
		watchdog.Stop()
	}
	for {
		select {
		case <-c.ctx.Done():
			if moving {
				stopMovement("shutdown")
			}
			return
		case <-watchdog.C:
			if moving {
				c.mu.Lock()
				c.status.WatchdogStops++
				c.mu.Unlock()
				stopMovement("watchdog")
			}
			continue
		case <-c.wake:
		}
		c.mu.Lock()
		cmd := c.pending
		c.pending = nil
		c.mu.Unlock()
		if cmd == nil {
			continue
		}
		if cmd.stop {
			if moving {
				stopMovement("recorder")
			}
			cmd.complete(nil)
			continue
		}
		// If a new command arrives as the watchdog expires, service the
		// expired movement before starting another camera operation.
		if moving && !c.now().Before(deadline) {
			stopMovement("watchdog")
		}
		budget := 8 * time.Second
		if moving {
			budget = min(budget, max(time.Millisecond, deadline.Sub(c.now())))
		}
		ctx, cancel, err := c.commandContext(cmd, budget)
		if err != nil {
			cmd.complete(err)
			continue
		}
		p, err := c.lens(ctx)
		if ctx.Err() != nil {
			err = ErrUnavailable
		}
		cancel()
		if err != nil {
			c.fail("move", err)
			cmd.complete(err)
			continue
		}
		mixedAbsoluteZoom := cmd.zoom != 0 && !p.capability.ContinuousZoom && (cmd.pan != 0 || cmd.tilt != 0)
		if ((cmd.pan != 0 || cmd.tilt != 0) && !p.capability.PanTilt) || (cmd.zoom != 0 && !p.capability.Zoom) ||
			mixedAbsoluteZoom || (cmd.preset != "" && p.capability.MaxPresets == 0) {
			c.fail("move", ErrUnsupported)
			cmd.complete(ErrUnsupported)
			continue
		}
		budget = 3 * time.Second
		if moving {
			budget = min(budget, max(time.Millisecond, deadline.Sub(c.now())))
		}
		ctx, cancel, err = c.commandContext(cmd, budget)
		if err != nil {
			cmd.complete(err)
			continue
		}
		operation, content, err := c.movement(ctx, p, cmd)
		if ctx.Err() != nil {
			err = ErrUnavailable
		}
		cancel()
		if err != nil {
			c.fail("move", err)
			cmd.complete(err)
			continue
		}
		ctx, cancel, err = c.commandContext(cmd, min(3*time.Second, c.maxMove))
		if err != nil {
			cmd.complete(err)
			continue
		}
		// A transport error may occur after the camera starts moving. Track
		// every sent movement, including preset recall and absolute zoom.
		setMoving(true)
		deadline = c.now().Add(c.maxMove)
		watchdog.Reset(c.maxMove)
		err = c.soap.call(ctx, p.ptzPath, ptzNamespace, operation, content, nil)
		cancel()
		if err != nil {
			c.fail(operation, err)
		} else {
			c.mu.Lock()
			c.status.Moves++
			c.mu.Unlock()
			c.logger.Info("ptz move sent", "operation", operation, "pan", cmd.pan, "tilt", cmd.tilt, "zoom", cmd.zoom,
				"watchdog_seconds", c.maxMove.Seconds(), "camera_timeout_seconds", p.timeout.Seconds())
		}
		cmd.complete(err)
	}
}

// stop retries briefly. Its context survives shutdown so a moving camera is
// always told to stop. Success alone clears the controller's movement state.
func (c *Controller) stop(reason string) error {
	c.mu.Lock()
	p := c.profile
	c.mu.Unlock()
	if p == nil {
		return ErrUnavailable
	}
	content := "<t:ProfileToken>" + xmlText(c.profileToken) + "</t:ProfileToken>" +
		fmt.Sprintf("<t:PanTilt>%t</t:PanTilt><t:Zoom>%t</t:Zoom>", p.panSpace != "", p.zoomSpace != "" || p.absoluteZoom != "")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		err = c.soap.call(attemptCtx, p.ptzPath, ptzNamespace, "Stop", content, nil)
		attemptCancel()
		if err == nil || errors.Is(err, ErrAuthentication) || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		c.fail("stop", err)
		return err
	}
	c.mu.Lock()
	c.status.Stops++
	c.mu.Unlock()
	c.logger.Info("ptz stop sent", "reason", reason)
	return nil
}

func (c *Controller) movement(ctx context.Context, p *lensProfile, cmd *command) (string, string, error) {
	profile := "<t:ProfileToken>" + xmlText(c.profileToken) + "</t:ProfileToken>"
	if cmd.preset != "" {
		return "GotoPreset", profile + "<t:PresetToken>" + xmlText(cmd.preset) + "</t:PresetToken>", nil
	}
	if cmd.zoom != 0 && !p.capability.ContinuousZoom {
		var status struct {
			PTZStatus struct {
				Position struct {
					Zoom *struct {
						X float64 `xml:"x,attr"`
					}
				}
			}
		}
		if err := c.soap.call(ctx, p.ptzPath, ptzNamespace, "GetStatus", profile, &status); err != nil {
			return "", "", err
		}
		position := status.PTZStatus.Position.Zoom
		if position == nil || math.IsNaN(position.X) || math.IsInf(position.X, 0) {
			return "", "", ErrUnavailable
		}
		target := math.Max(0, math.Min(1, position.X+math.Copysign(0.1, cmd.zoom)))
		return "AbsoluteMove", profile + "<t:Position>" +
			fmt.Sprintf(`<tt:Zoom x="%.3f" space="%s"/>`, target, xmlText(p.absoluteZoom)) + "</t:Position>", nil
	}
	velocity := ""
	if p.panSpace != "" {
		velocity += fmt.Sprintf(`<tt:PanTilt x="%.3f" y="%.3f" space="%s"/>`, cmd.pan, cmd.tilt, xmlText(p.panSpace))
	}
	if p.zoomSpace != "" {
		velocity += fmt.Sprintf(`<tt:Zoom x="%.3f" space="%s"/>`, cmd.zoom, xmlText(p.zoomSpace))
	}
	return "ContinuousMove", profile + "<t:Velocity>" + velocity + "</t:Velocity>" +
		"<t:Timeout>PT" + strconv.FormatFloat(p.timeout.Seconds(), 'f', -1, 64) + "S</t:Timeout>", nil
}

// Presets lists stored positions.
func (c *Controller) Presets(ctx context.Context) ([]Preset, error) {
	p, err := c.lens(ctx)
	if err != nil {
		return nil, err
	}
	var response struct {
		Preset []struct {
			Token string `xml:"token,attr"`
			Name  string
		}
	}
	if err := c.soap.call(ctx, p.ptzPath, ptzNamespace, "GetPresets", "<t:ProfileToken>"+xmlText(c.profileToken)+"</t:ProfileToken>", &response); err != nil {
		return nil, err
	}
	presets := make([]Preset, 0, len(response.Preset))
	for _, preset := range response.Preset {
		if len(presets) == 256 {
			break
		}
		if tokenPattern.MatchString(preset.Token) && len(preset.Name) <= 128 && headerText(preset.Name) {
			presets = append(presets, Preset{Token: preset.Token, Name: preset.Name})
		}
	}
	return presets, nil
}

// GotoPreset moves to a stored position.
func (c *Controller) GotoPreset(ctx context.Context, token string) error {
	if !tokenPattern.MatchString(token) {
		return ErrUnsupported
	}
	result := make(chan error, 1)
	c.submit(command{preset: token, ctx: ctx, result: result})
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ErrUnavailable
	case <-c.ctx.Done():
		return ErrUnavailable
	}
}

// SetPreset stores the current position under an optional existing token and
// returns the camera's token for it.
func (c *Controller) SetPreset(ctx context.Context, name, token string) (string, error) {
	if (token != "" && !tokenPattern.MatchString(token)) || len(name) > 64 || !headerText(name) {
		return "", ErrUnsupported
	}
	p, err := c.lens(ctx)
	if err != nil {
		return "", err
	}
	content := "<t:ProfileToken>" + xmlText(c.profileToken) + "</t:ProfileToken>"
	if name != "" {
		content += "<t:PresetName>" + xmlText(name) + "</t:PresetName>"
	}
	if token != "" {
		content += "<t:PresetToken>" + xmlText(token) + "</t:PresetToken>"
	}
	var response struct{ PresetToken string }
	if err := c.soap.call(ctx, p.ptzPath, ptzNamespace, "SetPreset", content, &response); err != nil {
		return "", err
	}
	if !tokenPattern.MatchString(response.PresetToken) {
		return "", ErrUnavailable
	}
	return response.PresetToken, nil
}

// RemovePreset deletes a stored position.
func (c *Controller) RemovePreset(ctx context.Context, token string) error {
	if !tokenPattern.MatchString(token) {
		return ErrUnsupported
	}
	p, err := c.lens(ctx)
	if err != nil {
		return err
	}
	return c.soap.call(ctx, p.ptzPath, ptzNamespace, "RemovePreset", "<t:ProfileToken>"+xmlText(c.profileToken)+"</t:ProfileToken><t:PresetToken>"+xmlText(token)+"</t:PresetToken>", nil)
}

func (c *Controller) fail(operation string, err error) {
	label := ErrorClass(err)
	c.mu.Lock()
	c.status.Failures++
	c.status.LastFailure = operation + ":" + label
	c.mu.Unlock()
	c.logger.Warn("ptz command failed", "operation", operation, "failure", label)
}

// ErrorClass maps an error to a fixed diagnostic label.
func ErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrAuthentication):
		return "authentication"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrRefused):
		return "refused"
	default:
		return "unavailable"
	}
}

// lens returns the cached profile, discovering it at most once at a time.
func (c *Controller) lens(ctx context.Context) (*lensProfile, error) {
	c.mu.Lock()
	if c.profile != nil && c.now().Before(c.expires) {
		p := c.profile
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return nil, ErrUnavailable
	}
	c.mu.Lock()
	if c.profile != nil && c.now().Before(c.expires) {
		p := c.profile
		c.mu.Unlock()
		return p, nil
	}
	if c.now().Before(c.retryAfter) {
		p := c.profile
		c.mu.Unlock()
		if p != nil {
			// Keep serving the last validated profile while the camera is unreachable.
			return p, nil
		}
		return nil, ErrUnavailable
	}
	c.mu.Unlock()
	p, err := c.discover(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.retryAfter = c.now().Add(30 * time.Second)
		if c.profile != nil {
			return c.profile, nil
		}
		return nil, err
	}
	c.profile, c.expires = p, c.now().Add(10*time.Minute)
	return p, nil
}

type rangeXY struct{ Min, Max *float64 }
type ptzSpace struct {
	URI            string
	XRange, YRange rangeXY
}

func (c *Controller) discover(ctx context.Context) (*lensProfile, error) {
	c.soap.syncClock(ctx)
	var services struct {
		Service []struct {
			Namespace, XAddr string
		}
	}
	if err := c.soap.call(ctx, devicePath, deviceNamespace, "GetServices", "<t:IncludeCapability>false</t:IncludeCapability>", &services); err != nil {
		return nil, err
	}
	paths := map[string]string{}
	for _, service := range services.Service {
		if path, ok := c.servicePath(service.XAddr); ok && (service.Namespace == mediaNamespace || service.Namespace == ptzNamespace) {
			paths[service.Namespace] = path
		}
	}
	if paths[mediaNamespace] == "" || paths[ptzNamespace] == "" {
		return nil, ErrUnsupported
	}
	var profile struct {
		Profile struct {
			Token            string `xml:"token,attr"`
			PTZConfiguration *struct {
				Token     string `xml:"token,attr"`
				NodeToken string
			}
		}
	}
	if err := c.soap.call(ctx, paths[mediaNamespace], mediaNamespace, "GetProfile", "<t:ProfileToken>"+xmlText(c.profileToken)+"</t:ProfileToken>", &profile); err != nil {
		return nil, err
	}
	configuration := profile.Profile.PTZConfiguration
	if profile.Profile.Token != c.profileToken || configuration == nil || !tokenPattern.MatchString(configuration.Token) || !tokenPattern.MatchString(configuration.NodeToken) {
		return nil, ErrUnsupported
	}
	var node struct {
		PTZNode struct {
			SupportedPTZSpaces struct {
				PanTilt      []ptzSpace `xml:"ContinuousPanTiltVelocitySpace"`
				Zoom         []ptzSpace `xml:"ContinuousZoomVelocitySpace"`
				AbsoluteZoom []ptzSpace `xml:"AbsoluteZoomPositionSpace"`
			}
			MaximumNumberOfPresets int
			HomeSupported          bool
		}
	}
	if err := c.soap.call(ctx, paths[ptzNamespace], ptzNamespace, "GetNode", "<t:NodeToken>"+xmlText(configuration.NodeToken)+"</t:NodeToken>", &node); err != nil {
		return nil, err
	}
	var options struct {
		PTZConfigurationOptions struct {
			PTZTimeout struct{ Min, Max string }
		}
	}
	if err := c.soap.call(ctx, paths[ptzNamespace], ptzNamespace, "GetConfigurationOptions", "<t:ConfigurationToken>"+xmlText(configuration.Token)+"</t:ConfigurationToken>", &options); err != nil {
		return nil, err
	}
	spaces := node.PTZNode.SupportedPTZSpaces
	result := &lensProfile{ptzPath: paths[ptzNamespace], configuration: configuration.Token,
		panSpace: velocitySpace(spaces.PanTilt, true), zoomSpace: velocitySpace(spaces.Zoom, false), absoluteZoom: positionSpace(spaces.AbsoluteZoom)}
	if result.zoomSpace == "" && result.absoluteZoom != "" {
		// Some cameras advertise an absolute zoom space without a zoom lens;
		// only a camera that reports its zoom position can step it.
		var status struct {
			PTZStatus struct {
				Position struct{ Zoom *struct{} }
			}
		}
		if err := c.soap.call(ctx, paths[ptzNamespace], ptzNamespace, "GetStatus", "<t:ProfileToken>"+xmlText(c.profileToken)+"</t:ProfileToken>", &status); err != nil || status.PTZStatus.Position.Zoom == nil {
			result.absoluteZoom = ""
		}
	}
	result.timeout = c.maxMove
	minimum, okMin := parseDuration(options.PTZConfigurationOptions.PTZTimeout.Min)
	maximum, okMax := parseDuration(options.PTZConfigurationOptions.PTZTimeout.Max)
	if okMin && okMax && minimum <= maximum {
		result.timeout = max(minimum, min(result.timeout, maximum))
	}
	// Camera timeout and local watchdog are independent. Some cameras only
	// accept 180 seconds; our worker must still send Stop at maxMove.
	presets := node.PTZNode.MaximumNumberOfPresets
	if presets < 0 || presets > 1024 {
		presets = 0
	}
	result.capability = Capability{PanTilt: result.panSpace != "", ContinuousZoom: result.zoomSpace != "",
		Zoom: result.zoomSpace != "" || result.absoluteZoom != "", MaxPresets: presets, Home: node.PTZNode.HomeSupported}
	c.logger.Info("ptz lens discovered", "pan_tilt", result.capability.PanTilt, "zoom", result.capability.Zoom,
		"continuous_zoom", result.capability.ContinuousZoom, "max_presets", presets, "home", result.capability.Home,
		"timeout_seconds", int(result.timeout/time.Second))
	return result, nil
}

// servicePath accepts only plain HTTP service addresses on the configured
// camera endpoint, so discovery cannot redirect credentials elsewhere.
func (c *Controller) servicePath(address string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(u.Path) > 128 || !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	base, _ := url.Parse(c.soap.base)
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return u.Path, u.Hostname() == base.Hostname() && port == base.Port()
}

// velocitySpace prefers the generic space whose ranges cover -1..1, the
// scale Move uses.
func velocitySpace(spaces []ptzSpace, panTilt bool) string {
	covers := func(r rangeXY) bool { return r.Min != nil && r.Max != nil && *r.Min <= -1 && *r.Max >= 1 }
	chosen := ""
	for _, s := range spaces {
		if s.URI == "" || len(s.URI) > 256 || !covers(s.XRange) || (panTilt && !covers(s.YRange)) {
			continue
		}
		if strings.HasSuffix(s.URI, "VelocityGenericSpace") {
			return s.URI
		}
		if chosen == "" {
			chosen = s.URI
		}
	}
	return chosen
}

func positionSpace(spaces []ptzSpace) string {
	for _, s := range spaces {
		if s.URI != "" && len(s.URI) <= 256 && s.XRange.Min != nil && s.XRange.Max != nil && *s.XRange.Min <= 0 && *s.XRange.Max >= 1 {
			return s.URI
		}
	}
	return ""
}

var durationPattern = regexp.MustCompile(`^P(?:(\d+)D)?T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$`)

func parseDuration(value string) (time.Duration, bool) {
	m := durationPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(m) != 5 {
		return 0, false
	}
	seconds, found := 0.0, false
	for i, multiplier := range []float64{86400, 3600, 60, 1} {
		if m[i+1] == "" {
			continue
		}
		found = true
		v, err := strconv.ParseFloat(m[i+1], 64)
		if err != nil {
			return 0, false
		}
		seconds += v * multiplier
	}
	if !found || seconds < 0 || seconds > 86400 {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}
