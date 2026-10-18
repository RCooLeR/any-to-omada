package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
	"github.com/RCooLeR/any-to-omada/internal/tpmarker"
)

// callbackStatus reports transport and application-authentication state separately from
// event counters; acknowledgements do not prove recorder history acceptance.
type callbackStatus struct {
	State                    string `json:"state"`
	Registrations            uint64 `json:"registrations"`
	Connections              uint64 `json:"connections"`
	EventsWritten            uint64 `json:"events_written"`
	EventsSuppressed         uint64 `json:"events_suppressed_by_settings"`
	EventsUnmapped           uint64 `json:"events_unmapped"`
	EventsDropped            uint64 `json:"events_dropped"`
	EventsAcknowledged       uint64 `json:"events_acknowledged"`
	EventsRejected           uint64 `json:"events_rejected"`
	EventsUnacknowledged     uint64 `json:"events_unacknowledged"`
	EventsPending            int    `json:"events_pending"`
	ApplicationAuthenticated bool   `json:"application_authenticated"`
	HeartbeatsReceived       uint64 `json:"heartbeats_received"`
	RecorderDeclarationSeen  bool   `json:"recorder_declaration_seen"`
	LastFailure              string `json:"last_failure,omitempty"`
}

// callbackAttempt owns one recorder registration, its cancellation, and the bounded event
// queue discarded when that registration is replaced.
type callbackAttempt struct {
	registration omadafront.CallbackRequest
	cancel       context.CancelFunc
	events       chan omadalink.Event
}

// callback owns one recorder session per virtual lens. Its context is the daemon
// lifetime, never the HTTP request that registered the recorder.
type callback struct {
	ctx      context.Context
	identity omadalink.DeclarationIdentity
	logger   *slog.Logger
	// mu guards attempts, lifecycle and counters; no network I/O holds it.
	mu     sync.Mutex
	active *callbackAttempt
	closed bool
	status callbackStatus
	alarms alarmTracker
	wg     sync.WaitGroup
	dial   func(context.Context, string, string) (net.Conn, error)
	// passthrough is wired before registration and dispatches only local virtual
	// camera management operations after callback authentication.
	passthrough func(json.RawMessage) json.RawMessage
	// credentials is derived and assigned before any recorder registration.
	credentials *omadalink.ApplicationCredentials
	// allow, when set, decides from the virtual detection settings whether an
	// alarm start may be forwarded. It is wired before sources start.
	allow func(omadalink.EventType) bool
	// intrusionSince holds the latest open intrusion start, or zero. The
	// guarded tracker aggregates overlapping source intervals for the marker.
	intrusionSince atomic.Int64
}

// maxMarkerAlert bounds an alert whose stop edge was lost.
const maxMarkerAlert = 10 * time.Minute

// markerState reports whether an intrusion is open for the
// in-stream marker units. It never blocks the media path.
func (c *callback) markerState() tpmarker.State {
	since := c.intrusionSince.Load()
	return tpmarker.State{IntrusionActive: since != 0 && time.Since(time.Unix(0, since)) < maxMarkerAlert}
}

// configureCredentials derives callback account material before registration; callers must
// not replace it while a session is running.
func (c *callback) configureCredentials(username, password string) error {
	credentials, err := omadalink.NewApplicationCredentials(username, password)
	if err != nil {
		return err
	}
	c.credentials = credentials
	return nil
}

// newCallback creates an unregistered worker with a stable locally administered MAC derived
// from its virtual camera ID.
func newCallback(ctx context.Context, id, ip string, logger *slog.Logger) *callback {
	hash := sha256.Sum256([]byte("any-to-omada/local-camera/" + id))
	var mac [6]byte
	copy(mac[:], hash[:6])
	mac[0] = mac[0]&0xfc | 0x02 // Stable locally administered unicast identity.
	return &callback{ctx: ctx, identity: omadalink.DeclarationIdentity{IP: netip.MustParseAddr(ip), MAC: mac, Name: id},
		logger: logger, status: callbackStatus{State: "unregistered"}, dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
}

// register replaces a changed registration, cancels its predecessor, and starts one
// reconnecting worker; identical registrations are idempotent.
func (c *callback) register(registration omadafront.CallbackRequest) error {
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return errors.New("callback worker stopped")
	}
	previous := c.active
	if previous != nil && previous.registration == registration {
		c.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(c.ctx)
	attempt := &callbackAttempt{registration: registration, cancel: cancel, events: make(chan omadalink.Event, 64)}
	c.releaseAccountState()
	c.active = attempt
	c.status.State = "connecting"
	c.status.Registrations++
	c.status.RecorderDeclarationSeen = false
	c.status.ApplicationAuthenticated = false
	c.status.LastFailure = ""
	c.wg.Add(1)
	c.mu.Unlock()
	if previous != nil {
		previous.cancel()
	}
	go func() { defer c.wg.Done(); c.run(ctx, attempt) }()
	return nil
}

// stop cancels the active registration only when its recorder address and port match the
// request.
func (c *callback) stop(ip string, port int) {
	c.mu.Lock()
	attempt := c.active
	if attempt == nil || attempt.registration.IP != ip || attempt.registration.Port != port {
		c.mu.Unlock()
		return
	}
	c.active = nil
	c.releaseAccountState()
	c.status.State = "unregistered"
	c.mu.Unlock()
	attempt.cancel()
}

// close prevents new registrations, cancels the active worker, and waits for all callback
// attempts to finish.
func (c *callback) close() {
	c.mu.Lock()
	c.closed = true
	attempt := c.active
	c.active = nil
	c.releaseAccountState()
	c.status.State = "stopped"
	c.mu.Unlock()
	if attempt != nil {
		attempt.cancel()
	}
	c.wg.Wait()
}

// releaseAccountState runs under mu before the old attempt loses ownership.
// Its later deferred update is ignored, so count unresolved writes here once.
func (c *callback) releaseAccountState() {
	c.status.EventsUnacknowledged += uint64(c.status.EventsPending)
	c.status.EventsPending = 0
	c.status.ApplicationAuthenticated = false
	c.alarms = nil
	c.intrusionSince.Store(0)
}

// snapshot copies callback state and counters under the lifecycle mutex.
func (c *callback) snapshot() callbackStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// update applies a status change only while the attempt still owns the registration; change
// runs under mu and must not perform I/O.
func (c *callback) update(attempt *callbackAttempt, change func(*callbackStatus)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == attempt {
		change(&c.status)
	}
}

// run reconnects a callback with bounded exponential backoff and discards queued live events
// after a failed session instead of replaying stale alarms.
func (c *callback) run(ctx context.Context, attempt *callbackAttempt) {
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		c.update(attempt, func(s *callbackStatus) {
			s.State = "connecting"
			s.RecorderDeclarationSeen = false
			s.ApplicationAuthenticated = false
		})
		started := time.Now()
		failure := c.session(ctx, attempt)
		if ctx.Err() != nil {
			return
		}
		c.update(attempt, func(s *callbackStatus) {
			s.State = "reconnecting"
			s.LastFailure = failure
			c.alarms = nil
			c.intrusionSince.Store(0)
		})
		// Live notifications cannot be replayed as current alarms after reconnect.
		for len(attempt.events) > 0 {
			<-attempt.events
			c.update(attempt, func(s *callbackStatus) { s.EventsDropped++ })
		}
		if time.Since(started) > time.Minute {
			backoff = 5 * time.Second
		}
		c.logger.Warn("native callback disconnected", "stage", failure, "retry_seconds", int(backoff.Seconds()))
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// send translates one source edge and atomically admits its full notification set to the
// active queue, returning a fixed delivery outcome.
func (c *callback) send(event cameraevents.Event) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	candidate := c.alarms.clone()
	wires, result, suppressed := candidate.apply(event, time.Now(), c.allow)
	c.status.EventsSuppressed += suppressed
	if result != "queued" {
		if result == "unmapped" || result == "ambiguous_stop" {
			c.status.EventsUnmapped++
		} else if result == "tracking_full" {
			c.status.EventsDropped++
		}
		return result
	}
	if c.active == nil || c.status.State != "connected" {
		c.status.EventsDropped++
		return "disconnected"
	}
	if !c.commitAlarms(candidate, wires) {
		c.status.EventsDropped++
		return "queue_full"
	}
	return "queued"
}

// commitAlarms runs under mu; every producer shares that lock. A mixed-class
// notification is admitted atomically, never partially forwarded or tracked.
func (c *callback) commitAlarms(candidate alarmTracker, wires []omadalink.Event) bool {
	if len(wires) > cap(c.active.events)-len(c.active.events) {
		return false
	}
	for _, wire := range wires {
		c.active.events <- wire
	}
	c.alarms = candidate
	c.intrusionSince.Store(candidate.intrusionStart())
	return true
}

// expireAlarms is driven by the existing session loop, not per-event goroutines.
// A full queue retains the deadline for retry; reconnect discards that state.
func (c *callback) expireAlarms(attempt *callbackAttempt, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != attempt || c.status.State != "connected" || len(c.alarms) == 0 {
		return
	}
	candidate := c.alarms.clone()
	wires := candidate.expire(now)
	c.commitAlarms(candidate, wires)
}

// sourceDisconnected invalidates intervals whose closing edges can no longer
// arrive. The session loop retries their stops if the callback queue is full.
func (c *callback) sourceDisconnected() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for _, types := range c.alarms {
		for eventType, hold := range types {
			hold.expires = now
			types[eventType] = hold
		}
	}
}

// callbackAddress builds the recorder endpoint from the validated callback registration.
func callbackAddress(attempt *callbackAttempt) string {
	return net.JoinHostPort(attempt.registration.IP, strconv.Itoa(attempt.registration.Port))
}
