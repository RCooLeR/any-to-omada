package app

import (
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

const (
	maxPendingEventAcks = 64
	eventAckTimeout     = 30 * time.Second
)

type pendingEventAck struct {
	event omadalink.Event
	sent  time.Time
}

// pendingEventAcks belongs to one application loop; it never survives reconnect.
type pendingEventAcks struct{ events map[uint16]pendingEventAck }

func newPendingEventAcks() *pendingEventAcks {
	return &pendingEventAcks{events: make(map[uint16]pendingEventAck)}
}

func (p *pendingEventAcks) expire(now time.Time) int {
	removed := 0
	for id, event := range p.events {
		if now.Sub(event.sent) >= eventAckTimeout {
			delete(p.events, id)
			removed++
		}
	}
	return removed
}

func (p *pendingEventAcks) nextAvailableID(id uint16) uint16 {
	for {
		if _, used := p.events[id]; !used {
			return id
		}
		id, _ = omadalink.NextMessageID(id)
	}
}

func (c *callback) acknowledgeEvent(attempt *callbackAttempt, pending *pendingEventAcks, message callbackMessage) bool {
	event, ok := pending.events[message.ID]
	if !ok || !message.outerErrorPresent || message.outerErrorCode == 0 && message.notifyErrorCode == nil {
		return false
	}
	delete(pending.events, message.ID)
	code := message.outerErrorCode
	if code == 0 {
		code = *message.notifyErrorCode
	}
	accepted := code == 0
	c.update(attempt, func(s *callbackStatus) {
		s.EventsPending = len(pending.events)
		if accepted {
			s.EventsAcknowledged++
		} else {
			s.EventsRejected++
		}
	})
	// An application ACK is not proof of recording history or channel attribution.
	c.logger.Info("native event acknowledged", "message_id", message.ID, "event_type", int(event.event.Type),
		"event_status", event.event.Status, "accepted", accepted, "error_code", code, "recording_history_verified", false)
	return true
}
