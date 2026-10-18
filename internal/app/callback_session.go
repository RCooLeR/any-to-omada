package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/omadafront"
	"github.com/RCooLeR/any-to-omada/internal/omadalink"
)

type callbackMessage struct {
	ID                uint16          `json:"id"`
	Method            string          `json:"method"`
	RequestData       json.RawMessage `json:"requestData"`
	ResponseData      json.RawMessage `json:"responseData"`
	peerVersion       string
	responseCode      int
	outerErrorPresent bool
	outerErrorCode    int
	notifyErrorCode   *int
}

func (c *callback) session(ctx context.Context, attempt *callbackAttempt) string {
	raw, err := c.dial(ctx, "tcp", callbackAddress(attempt))
	if err != nil {
		return "dial"
	}
	conn, err := omadalink.Handshake(ctx, raw, attempt.registration.AuthCode)
	if err != nil {
		if detail, ok := omadalink.FailureDiagnostics(err); ok {
			fields := []any{"error", err,
				"handshake_stage", detail.Stage, "received_bytes", detail.ReceivedBytes, "sent_bytes", detail.SentBytes,
				"timed_out", errors.Is(err, context.DeadlineExceeded), "recorder_port", attempt.registration.Port}
			if detail.Reason != "" {
				fields = append(fields, "failure_reason", detail.Reason)
			}
			if detail.PrefixCategory != "" {
				fields = append(fields, "frame_prefix", detail.PrefixCategory)
			}
			if detail.PeerStepPresent {
				fields = append(fields, "peer_step", detail.PeerStep)
			}
			if detail.PeerErrorCodePresent {
				fields = append(fields, "peer_error_code", detail.PeerErrorCode)
			}
			if detail.OfferVersion != "" {
				fields = append(fields, "version_offer_bytes", detail.OfferedBytes, "version_offer_kind", detail.OfferVersion)
			}
			c.logger.Warn("native callback authentication failed", fields...)
		} else {
			c.logger.Warn("native callback authentication failed", "error", err)
		}
		return "handshake"
	}
	defer conn.Close()
	return c.applicationSession(ctx, conn, attempt)
}

func (c *callback) applicationSession(ctx context.Context, conn net.Conn, attempt *callbackAttempt) string {
	authentication, err := omadalink.NewApplicationAuth(c.credentials)
	if err != nil {
		return "application_credentials"
	}
	cancelIO := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer cancelIO()
	id := omadalink.FirstMessageID
	declaration, err := omadalink.EncodeDeclaration(id, c.identity)
	if err != nil || writeCallback(conn, declaration) != nil {
		return "declaration_write"
	}
	id, _ = omadalink.NextMessageID(id)
	c.update(attempt, func(s *callbackStatus) { s.State = "connected"; s.Connections++; s.LastFailure = "" })
	c.logger.Info("native callback connected", "recorder_enrollment_verified", false)
	messages := make(chan callbackMessage, 8)
	readErrors := make(chan callbackReadFailure, 1)
	readerDone := make(chan struct{})
	readCtx, stopReader := context.WithCancel(ctx)
	defer func() { stopReader(); _ = conn.Close(); <-readerDone }()
	go func() {
		defer close(readerDone)
		c.readCallback(readCtx, conn, messages, readErrors)
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	alarmTicker := time.NewTicker(250 * time.Millisecond)
	defer alarmTicker.Stop()
	unanswered := 0
	var heartbeatsSent uint64
	pending := newPendingEventAcks()
	defer func() {
		c.update(attempt, func(s *callbackStatus) {
			s.EventsUnacknowledged += uint64(len(pending.events))
			s.EventsPending = 0
			s.ApplicationAuthenticated = false
		})
	}()
	for {
		// Backpressure must retain paired edges in order, especially a pulse's
		// synthetic stop. Keep the bounded queue until authenticated and until
		// ACK capacity becomes available instead of consuming and dropping it.
		var events <-chan omadalink.Event
		if authentication.Authenticated() && len(pending.events) < maxPendingEventAcks {
			events = attempt.events
		}
		select {
		case <-ctx.Done():
			return "stopped"
		case failure := <-readErrors:
			if ctx.Err() == nil {
				c.logCallbackReadFailure(failure, heartbeatsSent, unanswered)
			}
			return "read"
		case message := <-messages:
			switch message.Method {
			case "heartbeat":
				unanswered = 0
				c.update(attempt, func(s *callbackStatus) { s.HeartbeatsReceived++ })
			case "declaration":
				if validPeerVersion(message.peerVersion) {
					c.update(attempt, func(s *callbackStatus) { s.RecorderDeclarationSeen = true })
					c.logger.Info("native recorder declaration received")
				}
			case "response":
				if c.acknowledgeEvent(attempt, pending, message) {
					break
				}
				if message.responseCode != 0 {
					c.logger.Warn("native recorder returned an error", "message_id", message.ID, "error_code", message.responseCode)
				}
			case "passthrough":
				if !authentication.Authenticated() {
					frame, err := authentication.Challenge(message.ID)
					if err != nil || writeCallback(conn, frame) != nil {
						return "application_challenge"
					}
					break
				}
				if failure := c.writePassthrough(conn, message); failure != "" {
					return failure
				}
			case "auth":
				frame, accepted, err := authentication.Authenticate(message.ID, message.RequestData)
				if err != nil {
					return "application_authentication"
				}
				if writeCallback(conn, frame) != nil {
					return "application_authentication_write"
				}
				c.update(attempt, func(s *callbackStatus) { s.ApplicationAuthenticated = accepted })
				c.logger.Info("native callback account authentication", "accepted", accepted)
			default:
				// Do not execute or acknowledge unsupported tunneled operations;
				// name them, without values, so new recorder commands are visible.
				c.logger.Info("native callback operation unsupported", "message_id", message.ID,
					"method", callbackMethodLabel(message.Method), "request_shape", omadafront.RequestShape(message.RequestData))
			}
		case <-ticker.C:
			if expired := pending.expire(time.Now()); expired != 0 {
				c.update(attempt, func(s *callbackStatus) {
					s.EventsUnacknowledged += uint64(expired)
					s.EventsPending = len(pending.events)
				})
			}
			if unanswered > 3 {
				return "heartbeat_timeout"
			}
			id = pending.nextAvailableID(id)
			frame, err := omadalink.EncodeHeartbeat(id)
			if err != nil || writeCallback(conn, frame) != nil {
				return "heartbeat_write"
			}
			id, _ = omadalink.NextMessageID(id)
			unanswered++
			heartbeatsSent++
		case now := <-alarmTicker.C:
			c.expireAlarms(attempt, now)
		case event := <-events:
			id = pending.nextAvailableID(id)
			frame, err := omadalink.EncodeEvent(id, event)
			if err != nil || writeCallback(conn, frame) != nil {
				return "event_write"
			}
			pending.events[id] = pendingEventAck{event: event, sent: time.Now()}
			id, _ = omadalink.NextMessageID(id)
			c.update(attempt, func(s *callbackStatus) { s.EventsWritten++; s.EventsPending = len(pending.events) })
			c.logger.Info("native event written", "event_type", int(event.Type), "event_status", event.Status, "recorder_acceptance_verified", false)
		}
	}
}

func writeCallback(conn net.Conn, frame []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("callback write made no progress")
		}
		frame = frame[n:]
	}
	return nil
}

func validPeerVersion(value string) bool {
	if len(value) != 10 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
