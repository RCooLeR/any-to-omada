// Package app owns the translator daemon lifecycle. Source subscriptions are
// shared by physical device; virtual identities select one explicit lens.
package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/isapievents"
	"github.com/RCooLeR/any-to-omada/internal/onvifevents"
)

// adapters runs one capture generation per event protocol.
var adapters = map[string]func(context.Context, capture.Device, capture.Sink) error{
	config.ProtocolDVRIP: dvripcapture.Run,
	config.ProtocolISAPI: isapievents.Run,
	config.ProtocolONVIF: onvifevents.Run,
}

// sourceStatus reports physical subscription health and per-lens normalization counters
// separately from recorder event acceptance.
type sourceStatus struct {
	ID            string            `json:"id"`
	State         string            `json:"state"`
	Notifications uint64            `json:"notifications"`
	Normalized    uint64            `json:"normalized_edges"`
	Unrouted      uint64            `json:"unrouted_edges"`
	Malformed     uint64            `json:"malformed_notifications"`
	Reconnects    uint64            `json:"reconnects"`
	LastSeenUTC   time.Time         `json:"last_seen_utc,omitzero"`
	LastEventUTC  time.Time         `json:"last_event_utc,omitzero"`
	LensEdges     map[string]uint64 `json:"virtual_camera_edges"`
}

// source shares one physical subscription across configured virtual lenses, journaling
// native payloads before normalization and delivery.
type source struct {
	cfg     config.Source
	device  capture.Device
	store   capture.Sink
	cancel  context.CancelCauseFunc
	routes  map[int]string
	deliver func(string, cameraevents.Event) string
	// disconnected closes only this physical source's virtual alarm intervals.
	// It is wired before capture starts and called between capture generations.
	disconnected func(string)
	// mu guards counters and metadata; neither network nor storage calls hold it.
	mu            sync.Mutex
	status        sourceStatus
	metadataValue SourceMetadata
}

// routedEvent journals a normalized edge with its selected virtual lens and immediate
// callback-queue outcome.
type routedEvent struct {
	Event           cameraevents.Event `json:"event"`
	VirtualCameraID string             `json:"virtual_camera_id,omitempty"`
	Delivery        string             `json:"native_omada_delivery"`
}

// newSource constructs enabled lens routes and in-memory adapter credentials without opening
// a source connection.
func newSource(cfg config.Source, password string, cameras []config.Camera, store capture.Sink, cancel context.CancelCauseFunc) *source {
	s := &source{cfg: cfg, device: capture.Device{ID: cfg.ID, Host: cfg.Host, NativePort: cfg.NativePort, Username: cfg.Account.Username, Password: password}, store: store, cancel: cancel, routes: map[int]string{}, status: sourceStatus{ID: cfg.ID, State: "disabled", LensEdges: map[string]uint64{}}}
	if cfg.Enabled {
		s.status.State = "starting"
	}
	for _, camera := range cameras {
		if camera.Enabled && camera.SourceID == cfg.ID {
			s.routes[camera.SourceIndex] = camera.ID
			s.status.LensEdges[camera.ID] = 0
		}
	}
	return s
}

// snapshot copies source status and its per-lens counter map under the source mutex.
func (s *source) snapshot() sourceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.status
	result.LensEdges = map[string]uint64{}
	for id, count := range s.status.LensEdges {
		result.LensEdges[id] = count
	}
	return result
}

// state updates the subscription lifecycle label under the source mutex.
func (s *source) state(state string) { s.mu.Lock(); s.status.State = state; s.mu.Unlock() }

// startGeneration marks a reconnect and clears prior identity and encoder facts so stale
// metadata cannot mix with fresh observations.
func (s *source) startGeneration() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.State = "connecting"
	// A new capture must not combine a newly read model with prior-session
	// firmware or encoder settings when an optional read is rejected.
	s.metadataValue = SourceMetadata{}
}

// endGeneration schedules closure of alarm intervals only for virtual lenses routed from
// this source.
func (s *source) endGeneration() {
	if s.disconnected == nil {
		return
	}
	for _, cameraID := range s.routes {
		s.disconnected(cameraID)
	}
}

// write appends a source-scoped journal record and cancels the daemon on persistence
// failure.
func (s *source) write(protocol, kind string, data any) error {
	if err := s.store.Write(s.cfg.ID, protocol, kind, data); err != nil {
		s.cancel(errors.New("event persistence failed"))
		return err
	}
	return nil
}

// Write enforces adapter identity, persists native data, refreshes observed metadata, and
// routes normalized events by their explicit source index.
func (s *source) Write(id, protocol, kind string, data any) error {
	if id != s.cfg.ID {
		return errors.New("source adapter identity mismatch")
	}
	if err := s.write(protocol, kind, data); err != nil {
		return err
	}
	if protocol == config.ProtocolDVRIP && (kind == "identity" || kind == "configuration") {
		s.recordMetadata(data)
	}
	if (protocol == config.ProtocolISAPI || protocol == config.ProtocolONVIF) && kind == "identity" {
		s.recordIdentity(data)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.status.LastSeenUTC = now
	if kind == "subscription" || kind == "heartbeat" || kind == "event" {
		s.status.State = "receiving"
	}
	if kind == "event" {
		s.status.Notifications++
		s.status.LastEventUTC = now
	}
	s.mu.Unlock()
	if kind != "event" {
		return nil
	}
	events, err := cameraevents.Normalize(id, now, data, s.cfg.EventMappings)
	if err != nil {
		s.mu.Lock()
		s.status.Malformed++
		s.mu.Unlock()
		return s.write("normalized", "parse_failure", map[string]string{"category": "invalid_event_envelope"})
	}
	for _, event := range events {
		cameraID := s.routes[event.SourceIndex]
		delivery := "unsupported"
		if s.deliver != nil {
			delivery = s.deliver(cameraID, event)
		}
		if err := s.write("normalized", "event", routedEvent{event, cameraID, delivery}); err != nil {
			return err
		}
		s.mu.Lock()
		s.status.Normalized++
		if cameraID == "" {
			s.status.Unrouted++
		} else {
			s.status.LensEdges[cameraID]++
		}
		s.mu.Unlock()
	}
	return nil
}

// run retries failed capture generations with backoff up to five minutes, but stops after
// rejected credentials or daemon cancellation.
func (s *source) run(ctx context.Context) {
	backoff := 15 * time.Second
	for ctx.Err() == nil {
		s.startGeneration()
		started := time.Now()
		err := adapters[s.cfg.EventProtocol()](ctx, s.device, s)
		// A lost source connection cannot provide reliable stop edges. Schedule
		// closure before any reconnect, including authentication and shutdown exits.
		s.endGeneration()
		if ctx.Err() != nil {
			s.state("stopped")
			return
		}
		if errors.Is(err, capture.ErrAuthentication) {
			s.state("authentication_failed")
			return
		}
		s.state("reconnecting")
		s.mu.Lock()
		s.status.Reconnects++
		s.mu.Unlock()
		if time.Since(started) > time.Minute {
			backoff = 15 * time.Second
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			s.state("stopped")
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
	s.state("stopped")
}
