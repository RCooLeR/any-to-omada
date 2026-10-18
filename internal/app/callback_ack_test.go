package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

func TestEventAcknowledgementsRequirePendingIDAndBothErrorCodes(t *testing.T) {
	for _, test := range []struct {
		name, body        string
		handled, accepted bool
	}{
		{"accepted", `{"id":32775,"error_code":0,"responseData":{"notify_event":{"error_code":0}}}`, true, true},
		{"nested rejection", `{"id":32775,"error_code":0,"responseData":{"notify_event":{"error_code":-40106}}}`, true, false},
		{"outer rejection", `{"id":32775,"error_code":-40401,"responseData":{}}`, true, false},
		{"bare outer rejection", `{"id":32775,"error_code":-40401}`, true, false},
		{"missing nested status", `{"id":32775,"error_code":0,"responseData":{"notify_event":{}}}`, false, false},
		{"unrelated response", `{"id":32775,"error_code":0,"responseData":{"error_code":0}}`, false, false},
		{"unrelated ID", `{"id":1,"error_code":0,"responseData":{"notify_event":{"error_code":0}}}`, false, false},
		{"missing outer status", `{"id":32775,"method":"response","responseData":{"notify_event":{"error_code":0}}}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			c := newCallback(t.Context(), "fixture", "192.0.2.210", slog.New(slog.NewJSONHandler(&output, nil)))
			attempt := &callbackAttempt{}
			c.active = attempt
			pending := newPendingEventAcks()
			pending.events[32775] = pendingEventAck{event: omadalink.Event{Type: omadalink.EventHumanIntrusion, Status: 1}, sent: time.Now()}
			message, err := decodeCallbackMessage(json.RawMessage(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.acknowledgeEvent(attempt, pending, message); got != test.handled {
				t.Fatal("unexpected acknowledgement classification")
			}
			status := c.snapshot()
			if (status.EventsAcknowledged == 1) != test.accepted || (status.EventsRejected == 1) != (test.handled && !test.accepted) || len(pending.events) != 1-boolInt(test.handled) {
				t.Fatal("acknowledgement counters or pending state incorrect")
			}
			if test.handled && c.acknowledgeEvent(attempt, pending, message) {
				t.Fatal("duplicate acknowledgement counted twice")
			}
			if strings.Contains(output.String(), "responseData") {
				t.Fatal("raw payload logged")
			}
		})
	}
}

func TestCallbackOwnershipChangeClearsAuthenticationAndPendingAcks(t *testing.T) {
	for _, action := range []string{"stop", "close", "replace"} {
		t.Run(action, func(t *testing.T) {
			c := newCallback(t.Context(), "fixture", "192.0.2.210", slog.New(slog.NewTextHandler(io.Discard, nil)))
			c.dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
			request := omadafront.CallbackRequest{IP: "192.0.2.150", Port: 6000, AuthCode: "synthetic-old"}
			old := &callbackAttempt{registration: request, cancel: func() {}}
			c.active = old
			c.status.ApplicationAuthenticated = true
			c.status.EventsPending = 3
			switch action {
			case "stop":
				c.stop(request.IP, request.Port)
			case "close":
				c.close()
			case "replace":
				request.AuthCode = "synthetic-new"
				if err := c.register(request); err != nil {
					t.Fatal(err)
				}
			}
			status := c.snapshot()
			if status.ApplicationAuthenticated || status.EventsPending != 0 || status.EventsUnacknowledged != 3 {
				t.Fatal("old session status remained after ownership changed")
			}
			c.update(old, func(s *callbackStatus) { s.EventsUnacknowledged += 3 })
			c.close()
			if c.snapshot().EventsUnacknowledged != 3 {
				t.Fatal("unresolved old events counted twice")
			}
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestPendingEventAcknowledgementsExpireAndAvoidMessageIDReuse(t *testing.T) {
	now := time.Date(2026, 10, 16, 8, 43, 0, 0, time.UTC)
	pending := newPendingEventAcks()
	pending.events[65535] = pendingEventAck{sent: now.Add(-eventAckTimeout)}
	pending.events[32768] = pendingEventAck{sent: now.Add(-eventAckTimeout + time.Nanosecond)}
	if id := pending.nextAvailableID(65535); id != 32769 {
		t.Fatal("pending event ID reused around wrap")
	}
	if pending.expire(now) != 1 || len(pending.events) != 1 {
		t.Fatal("ack timeout boundary wrong")
	}
	if pending.nextAvailableID(65535) != 65535 {
		t.Fatal("expired ID was not released")
	}
	if pending.expire(now.Add(time.Nanosecond)) != 1 {
		t.Fatal("remaining acknowledgement did not expire")
	}
}
