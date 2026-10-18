// Package dvripcapture captures native Dahua/Imou notifications. Event sessions
// remain read-only; explicit Lighting sessions provide isolated operator tests.
package dvripcapture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

type timings struct {
	rpc       time.Duration
	keepAlive time.Duration
	cleanup   time.Duration
}

var defaultTimings = timings{rpc: 5 * time.Second, keepAlive: 20 * time.Second, cleanup: 3 * time.Second}

type received struct {
	frame frame
	err   error
}

type client struct {
	conn      net.Conn
	device    capture.Device
	sink      capture.Sink
	session   uint32
	requestID uint32
	frames    <-chan received
	timings   timings
	attached  bool
}

// Run logs identity, firmware, encoder and SmartMotionDetect configuration, plus
// unchanged native events. It never infers a class or retries authentication.
// Cancellation attempts event detach and logout within a separate bounded window.
func Run(ctx context.Context, device capture.Device, sink capture.Sink) error {
	return run(ctx, device, sink, defaultTimings)
}

func run(ctx context.Context, device capture.Device, sink capture.Sink, limits timings) (runErr error) {
	port := device.NativePort
	if port == 0 {
		port = 37777
	}
	if port < 1 || port > 65535 || device.Host == "" || sink == nil {
		return errors.New("invalid DVRIP capture configuration")
	}
	dialer := net.Dialer{Timeout: limits.rpc}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(device.Host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("connect DVRIP: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			runErr = errors.Join(runErr, err)
		}
	}()
	c := &client{conn: conn, device: device, sink: sink, requestID: 1, timings: limits}
	if err := c.login(ctx); err != nil {
		return errors.Join(err, ctx.Err())
	}
	frames := make(chan received, 4)
	stop := make(chan struct{})
	done := make(chan struct{})
	c.frames = frames
	go func() {
		defer close(done)
		for {
			packet, err := readFrame(conn)
			select {
			case frames <- received{frame: packet, err: err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), limits.cleanup)
		cleanupErr := c.cleanup(cleanupCtx)
		cancel()
		close(stop)
		closeErr := conn.Close()
		<-done
		// A second Close is normal for net.Conn; avoid adding net.ErrClosed.
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			runErr = errors.Join(runErr, closeErr)
		}
		runErr = errors.Join(runErr, cleanupErr)
	}()
	return c.capture(ctx)
}

func (c *client) login(ctx context.Context) (loginErr error) {
	if err := c.conn.SetDeadline(time.Now().Add(c.timings.rpc)); err != nil {
		return fmt.Errorf("set DVRIP login deadline: %w", err)
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(canceled)
		// Closing is deliberately avoided: a completed login can still log out.
		if err := c.conn.SetDeadline(time.Now()); err != nil {
			return
		}
	})
	defer func() {
		if !stop() {
			<-canceled
		}
		if loginErr == nil {
			if err := c.conn.SetDeadline(time.Time{}); err != nil {
				loginErr = fmt.Errorf("clear DVRIP login deadline: %w", err)
			}
		}
	}()
	if err := writeFrame(c.conn, challengeHeader(), nil); err != nil {
		return err
	}
	challenge, err := readFrame(c.conn)
	if err != nil {
		return err
	}
	payload, err := loginPayload(c.device.Username, c.device.Password, challenge.body)
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, loginHeader(), payload); err != nil {
		return err
	}
	answer, err := readFrame(c.conn)
	if err != nil {
		return err
	}
	if answer.header[8] != 0 || answer.header[9] != 8 {
		return capture.ErrAuthentication
	}
	c.session = binary.LittleEndian.Uint32(answer.header[16:20])
	return nil
}

func (c *client) capture(ctx context.Context) error {
	for _, request := range []struct {
		method string
		params any
	}{
		{method: "magicBox.getDeviceType"},
		{method: "magicBox.getSoftwareVersion"},
		{method: "configManager.getConfig", params: map[string]any{"name": "Encode"}},
		{method: "configManager.getConfig", params: map[string]any{"name": "SmartMotionDetect"}},
	} {
		if _, err := c.rpc(ctx, request.method, request.params); err != nil {
			return err
		}
	}
	// Mark the attempt before sending: if the reply is lost, detach still runs.
	c.attached = true
	answer, err := c.rpc(ctx, "eventManager.attach", map[string]any{"codes": []string{"All"}})
	if err != nil {
		return err
	}
	if err := requireSuccess(answer, "event attachment"); err != nil {
		return err
	}
	if err := c.sink.Write(c.device.ID, "dvrip", "subscription", map[string]any{"attached": true, "codes": []string{"All"}}); err != nil {
		return err
	}
	ticker := time.NewTicker(c.timings.keepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			answer, err := c.rpc(ctx, "global.keepAlive", map[string]any{"timeout": 30, "active": true})
			if err != nil {
				return err
			}
			if err := requireSuccess(answer, "keepalive"); err != nil {
				return err
			}
		case packet := <-c.frames:
			if _, err := c.consume(packet, 0); err != nil {
				return err
			}
		}
	}
}

func (c *client) rpc(ctx context.Context, method string, params any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timings.rpc)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.requestID++
	message := map[string]any{"method": method, "id": c.requestID, "session": c.session}
	if params != nil || method == "global.logout" {
		message["params"] = params
	}
	body, err := json.Marshal(message)
	if err != nil {
		return nil, errors.New("encode DVRIP request")
	}
	header := [32]byte{0: 0xf6}
	binary.LittleEndian.PutUint32(header[8:12], c.requestID)
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(body)))
	binary.LittleEndian.PutUint32(header[24:28], c.session)
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set DVRIP write deadline: %w", err)
	}
	started := time.Now()
	if err := writeFrame(c.conn, header, body); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("DVRIP %s: %w", method, ctx.Err())
		case packet := <-c.frames:
			answer, err := c.consume(packet, c.requestID)
			if err != nil {
				return nil, err
			}
			if answer != nil {
				if err := c.recordResponse(method, params, answer, time.Since(started)); err != nil {
					return answer, err
				}
				return answer, nil
			}
		}
	}
}

func (c *client) recordResponse(method string, params any, answer map[string]any, duration time.Duration) error {
	kind := "response"
	switch {
	case method == "global.keepAlive" && answer["result"] == true:
		kind = "heartbeat"
	case method == "magicBox.getDeviceType" || method == "magicBox.getSoftwareVersion":
		kind = "identity"
	case method == "configManager.getConfig":
		kind = "configuration"
	}
	// Keep native error codes and unknown fields intact; the shared sink owns
	// redaction. Recording a rejection does not assign authentication semantics.
	data := map[string]any{
		"method": method, "response": answer, "request_duration_ms": duration.Milliseconds(),
	}
	if method == "configManager.getConfig" {
		fields, _ := params.(map[string]any)
		if name, _ := fields["name"].(string); name == "Encode" || name == "SmartMotionDetect" {
			data["configuration_name"] = name
		}
	}
	return c.sink.Write(c.device.ID, "dvrip", kind, data)
}

func (c *client) consume(packet received, requestID uint32) (map[string]any, error) {
	if packet.err != nil {
		return nil, packet.err
	}
	messages, err := jsonMessages(packet.frame.body)
	if err != nil {
		return nil, err
	}
	var answer map[string]any
	for _, message := range messages {
		params, _ := message["params"].(map[string]any)
		if events, ok := params["eventList"].([]any); ok && len(events) > 0 {
			// Preserve the complete notification, including unknown nested payloads
			// and the device's own timestamps. Redaction belongs to the sink.
			if err := c.sink.Write(c.device.ID, "dvrip", "event", message); err != nil {
				return nil, err
			}
		}
		if id, ok := message["id"].(json.Number); ok && id.String() == strconv.FormatUint(uint64(requestID), 10) && requestID != 0 {
			answer = message
		}
	}
	return answer, nil
}

func requireSuccess(answer map[string]any, operation string) error {
	if answer["result"] != true {
		return fmt.Errorf("DVRIP %s rejected", operation)
	}
	return nil
}

func (c *client) cleanup(ctx context.Context) error {
	var cleanupErr error
	if c.attached {
		// Reserve half the cleanup window for logout if detach is unanswered.
		deadline, _ := ctx.Deadline()
		detachCtx, cancel := context.WithTimeout(ctx, max(time.Until(deadline)/2, time.Nanosecond))
		answer, err := c.rpc(detachCtx, "eventManager.detach", map[string]any{"codes": []string{"All"}})
		cancel()
		if err == nil {
			err = requireSuccess(answer, "event detach")
		}
		cleanupErr = errors.Join(cleanupErr, err)
	}
	answer, err := c.rpc(ctx, "global.logout", nil)
	if err == nil {
		err = requireSuccess(answer, "logout")
	}
	return errors.Join(cleanupErr, err)
}
