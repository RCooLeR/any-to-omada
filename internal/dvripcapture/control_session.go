package dvripcapture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

// ControlRequest addresses one authenticated native method. Object is a
// session-local factory handle; zero omits it. Sequence is the vendor command
// sequence and is also omitted when zero. SessionSequence prefixes its low byte
// with the authenticated session, as required by factory-backed PTZ commands.
// No credential fields belong here.
type ControlRequest struct {
	Method          string
	Params          any
	Object          uint32
	Sequence        uint32
	SessionSequence bool
}

// ControlCall sends one request without retries and returns decoded native
// fields for validated protocol adapters. Peer bodies must never be logged.
type ControlCall func(context.Context, ControlRequest) (map[string]any, error)

// ControlSession isolates physical controls from event capture and bounds native
// RPCs. It never retries a write. Only restoration reads reconnect a broken
// stream; callers own command serialization and cleanup after uncertain writes.
func ControlSession(ctx context.Context, device capture.Device, fn func(ControlCall) error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	port := device.NativePort
	if port == 0 {
		port = 37777
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(device.Host, strconv.Itoa(port)))
	if err != nil {
		return lightingFailure("session", "connect", nil)
	}
	defer func() { _ = conn.Close() }()
	c := &client{conn: conn, device: device, requestID: 1, timings: timings{rpc: 3 * time.Second}}
	if err := c.login(ctx); err != nil {
		if errors.Is(err, capture.ErrAuthentication) {
			return lightingFailure("session", "authentication_rejected", capture.ErrAuthentication)
		}
		return lightingFailure("session", "authentication_unavailable", nil)
	}
	broken := false
	call := func(ctx context.Context, request ControlRequest) (map[string]any, error) {
		method, params := request.Method, request.Params
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if broken {
			_ = conn.Close()
			// A partial frame destroys stream alignment. Only a fresh session
			// may read restoration state; never retry the activation write.
			if method != "configManager.getConfig" {
				return nil, lightingFailure(method, "session_unavailable", nil)
			}
			var err error
			nextConn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(device.Host, strconv.Itoa(port)))
			if err != nil {
				return nil, lightingFailure(method, "restore_reconnect", nil)
			}
			conn = nextConn
			c.conn, c.requestID = conn, 1
			if err := c.login(ctx); err != nil {
				return nil, lightingFailure(method, "restore_authentication", nil)
			}
			broken = false
		}
		deadline := time.Now().Add(3 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := conn.SetDeadline(deadline); err != nil {
			broken = true
			return nil, lightingFailure(method, "set_deadline", nil)
		}
		interrupted := make(chan struct{})
		stopInterrupt := context.AfterFunc(ctx, func() { defer close(interrupted); _ = conn.SetDeadline(time.Now()) })
		defer func() {
			if !stopInterrupt() {
				<-interrupted
			}
		}()
		c.requestID++
		message := map[string]any{"method": method, "params": params, "id": c.requestID, "session": c.session}
		if request.Object != 0 {
			message["object"] = request.Object
		}
		if request.Sequence != 0 {
			sequence := request.Sequence
			if request.SessionSequence {
				sequence = (c.session&0xffffff)<<8 | request.Sequence&0xff
			}
			message["seq"] = sequence
		}
		body, err := json.Marshal(message)
		if err != nil {
			return nil, lightingFailure(method, "encode", nil)
		}
		header := [32]byte{0: 0xf6}
		binary.LittleEndian.PutUint32(header[8:12], c.requestID)
		binary.LittleEndian.PutUint32(header[16:20], uint32(len(body)))
		binary.LittleEndian.PutUint32(header[24:28], c.session)
		if writeFrame(conn, header, body) != nil {
			broken = true
			return nil, lightingFailure(method, "write_outcome_unknown", nil)
		}
		// Ignore only a bounded number of late replies; a timed-out write
		// must not be confused with the following restoration read.
		for i := 0; i < 8; i++ {
			packet, err := readFrame(conn)
			if err != nil {
				broken = true
				return nil, lightingFailure(method, "read_response", ctx.Err())
			}
			messages, err := jsonMessages(packet.body)
			if err != nil {
				broken = true
				return nil, lightingFailure(method, "decode_response", nil)
			}
			for _, answer := range messages {
				if answer["id"] != json.Number(strconv.FormatUint(uint64(c.requestID), 10)) {
					continue
				}
				factory := false
				if strings.HasSuffix(method, ".factory.instance") {
					if number, ok := answer["result"].(json.Number); ok {
						object, err := strconv.ParseUint(string(number), 10, 32)
						factory = err == nil && object > 0
					}
				}
				if answer["result"] != true && !factory {
					return nil, lightingRejection(method, answer)
				}
				return answer, nil
			}
		}
		return nil, lightingFailure(method, "response_mismatch", nil)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := call(cleanup, ControlRequest{Method: "global.logout"}); err != nil {
			result = errors.Join(result, err)
		}
	}()
	return fn(call)
}
