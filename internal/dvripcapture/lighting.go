package dvripcapture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

// ErrLightingUnsupported means that the selected lens/profile does not expose
// exactly one WhiteLight entry in the observed Lighting_V2 configuration.
var ErrLightingUnsupported = errors.New("white light configuration unsupported")

// ErrLightingRestore means the test could not confirm restoration of the
// original light settings, including when another controller changed them.
var ErrLightingRestore = errors.New("white light restoration failed")

// Lighting owns a separate, short-lived native session for explicit operator
// controls. It does not share or interrupt the event subscription. Calls for a
// physical source must be serialized by the caller, including restoration.
type Lighting struct{ device capture.Device }

// NewLighting prepares the existing source endpoint without contacting it.
func NewLighting(device capture.Device) *Lighting { return &Lighting{device: device} }

// LightingSettings is a validated readback of the two fields a test pulse uses.
type LightingSettings struct {
	Mode       string `json:"mode"`
	Brightness int    `json:"brightness"`
}

// Settings reads the selected white-light fields without changing the camera.
func (l *Lighting) Settings(ctx context.Context, channel, profile int) (settings LightingSettings, result error) {
	result = l.session(ctx, func(call lightingCall) error {
		table, err := lightingTable(ctx, call, channel)
		if err != nil {
			return err
		}
		entry, err := whiteLightEntry(table, profile)
		if err != nil {
			return err
		}
		brightness, ok := brightnessValue(entry["PercentOfMaxBrightness"])
		if !ok {
			return ErrLightingUnsupported
		}
		settings = LightingSettings{Mode: entry["Mode"].(string), Brightness: brightness}
		return nil
	})
	return settings, result
}

// Available reads the selected white-light entry without changing the camera.
func (l *Lighting) Available(ctx context.Context, channel, profile int) error {
	return l.session(ctx, func(call lightingCall) error {
		table, err := lightingTable(ctx, call, channel)
		if err != nil {
			return err
		}
		_, err = whiteLightEntry(table, profile)
		return err
	})
}

// Pulse temporarily changes only the selected WhiteLight entry and restores
// its exact original fields after the pulse or cancellation. A lost write reply
// still triggers restoration. No uncertain write is retried. A restore error
// is returned because the light's final state then remains unknown.
func (l *Lighting) Pulse(ctx context.Context, channel, profile, brightness int, duration time.Duration) error {
	if brightness < 1 || brightness > 100 || duration < 100*time.Millisecond || duration > 5*time.Second {
		return ErrLightingUnsupported
	}
	return l.session(ctx, func(call lightingCall) (result error) {
		table, err := lightingTable(ctx, call, channel)
		if err != nil {
			return err
		}
		entry, err := whiteLightEntry(table, profile)
		if err != nil {
			return err
		}
		oldMode, oldBrightness := entry["Mode"], entry["PercentOfMaxBrightness"]
		entry["Mode"], entry["PercentOfMaxBrightness"] = "Manual", brightness
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			// Re-read before restoring so changes to other lenses/settings are
			// retained. Never blindly replay the original whole-camera table.
			current, restoreErr := lightingTable(cleanup, call, channel)
			if restoreErr == nil {
				var target map[string]any
				target, restoreErr = whiteLightEntry(current, profile)
				if restoreErr == nil {
					if target["Mode"] != "Manual" || !sameBrightness(target["PercentOfMaxBrightness"], brightness) {
						// Another controller changed this light; do not overwrite it.
						restoreErr = errors.New("white light changed during pulse; restoration skipped")
					} else {
						target["Mode"], target["PercentOfMaxBrightness"] = oldMode, oldBrightness
						_, restoreErr = call(cleanup, "configManager.setConfig", lightingWrite(channel, current))
					}
				}
			}
			if restoreErr != nil {
				result = errors.Join(result, ErrLightingRestore, restoreErr)
			}
		}()
		if _, err := call(ctx, "configManager.setConfig", lightingWrite(channel, table)); err != nil {
			return err
		}
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func sameBrightness(value any, brightness int) bool {
	number, ok := brightnessValue(value)
	return ok && number == brightness
}

func brightnessValue(value any) (int, bool) {
	var number float64
	switch value := value.(type) {
	case json.Number:
		var err error
		number, err = value.Float64()
		if err != nil {
			return 0, false
		}
	case float64:
		number = value
	case int:
		number = float64(value)
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 100 || math.Trunc(number) != number {
		return 0, false
	}
	return int(number), true
}

type lightingCall func(context.Context, string, any) (map[string]any, error)

func lightingTable(ctx context.Context, call lightingCall, channel int) ([]any, error) {
	if channel < 0 || channel > 65535 {
		return nil, ErrLightingUnsupported
	}
	answer, err := call(ctx, "configManager.getConfig", map[string]any{"name": "Lighting_V2", "channel": channel})
	if err != nil {
		return nil, err
	}
	params, _ := answer["params"].(map[string]any)
	if echoed, present := params["channel"]; present {
		number, ok := echoed.(json.Number)
		if !ok {
			return nil, ErrLightingUnsupported
		}
		value, err := number.Int64()
		if err != nil || value != int64(channel) {
			return nil, ErrLightingUnsupported
		}
	}
	table, ok := params["table"].([]any)
	if !ok || len(table) > 64 {
		return nil, ErrLightingUnsupported
	}
	return table, nil
}

// lightingWrite follows the channel-scoped configuration contract: table holds
// profiles for one lens, never the top-level array of every physical channel.
func lightingWrite(channel int, table []any) map[string]any {
	return map[string]any{"name": "Lighting_V2", "channel": channel, "options": []any{}, "table": table}
}

func whiteLightEntry(table []any, profile int) (map[string]any, error) {
	if profile < 0 || profile >= len(table) {
		return nil, ErrLightingUnsupported
	}
	entries, ok := table[profile].([]any)
	if !ok || len(entries) > 16 {
		return nil, ErrLightingUnsupported
	}
	var selected map[string]any
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, ErrLightingUnsupported
		}
		if entry["LightType"] == "WhiteLight" {
			if selected != nil {
				return nil, ErrLightingUnsupported
			}
			if mode, ok := entry["Mode"].(string); !ok || mode == "" || len(mode) > 64 {
				return nil, ErrLightingUnsupported
			}
			if _, ok := brightnessValue(entry["PercentOfMaxBrightness"]); !ok {
				return nil, ErrLightingUnsupported
			}
			selected = entry
		}
	}
	if selected == nil {
		return nil, ErrLightingUnsupported
	}
	return selected, nil
}

func (l *Lighting) session(ctx context.Context, fn func(lightingCall) error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	port := l.device.NativePort
	if port == 0 {
		port = 37777
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(l.device.Host, strconv.Itoa(port)))
	if err != nil {
		return lightingFailure("session", "connect", nil)
	}
	defer func() { _ = conn.Close() }()
	c := &client{conn: conn, device: l.device, requestID: 1, timings: timings{rpc: 3 * time.Second}}
	if err := c.login(ctx); err != nil {
		if errors.Is(err, capture.ErrAuthentication) {
			return lightingFailure("session", "authentication_rejected", capture.ErrAuthentication)
		}
		return lightingFailure("session", "authentication_unavailable", nil)
	}
	broken := false
	call := func(ctx context.Context, method string, params any) (map[string]any, error) {
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
			nextConn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(l.device.Host, strconv.Itoa(port)))
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
		body, err := json.Marshal(map[string]any{"method": method, "params": params, "id": c.requestID, "session": c.session})
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
				if answer["result"] != true {
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
		if _, err := call(cleanup, "global.logout", nil); err != nil {
			result = errors.Join(result, err)
		}
	}()
	return fn(call)
}
