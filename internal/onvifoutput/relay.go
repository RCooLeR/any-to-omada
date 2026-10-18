// Package onvifoutput provides bounded pulses on explicitly selected, advertised
// ONVIF relay outputs. A relay is not assumed to be a built-in camera siren.
package onvifoutput

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/onvifsoap"
)

const ioNamespace = "http://www.onvif.org/ver10/deviceIO/wsdl"

var secondsPattern = regexp.MustCompile(`^PT([0-5](?:\.[0-9]{1,6})?)S$`)

// ErrUnsupported means the configured relay is absent or is not a monostable
// output with a bounded device-side delay. Relay configuration is never changed.
var ErrUnsupported = errors.New("bounded ONVIF relay unavailable")

// Relay targets one named relay of a pinned source camera.
type Relay struct {
	soap  *onvifsoap.Client
	token string
}

// New prepares the source account without contacting or changing the device.
func New(host string, port int, username, password, token string) *Relay {
	return &Relay{soap: onvifsoap.New(host, port, username, password, 3*time.Second), token: token}
}

// Close releases idle connections.
func (r *Relay) Close() { r.soap.Close() }

// relayInfo identifies the relay service and its advertised reset duration,
// validated against the supported bounds without observing physical actuation.
type relayInfo struct {
	path, namespace string
	delay           time.Duration
}

// Available confirms that the output is advertised with a device-side reset.
func (r *Relay) Available(ctx context.Context) error { _, err := r.discover(ctx); return err }

// discover selects the configured relay only if it advertises monostable operation with a
// reset delay between 100 ms and five seconds.
func (r *Relay) discover(ctx context.Context) (relayInfo, error) {
	r.soap.SyncClock(ctx)
	var services struct {
		Service []struct{ Namespace, XAddr string }
	}
	if err := r.soap.Call(ctx, "/onvif/device_service", onvifsoap.DeviceNamespace, "GetServices", "<t:IncludeCapability>false</t:IncludeCapability>", &services); err != nil {
		return relayInfo{}, err
	}
	info := relayInfo{path: "/onvif/device_service", namespace: onvifsoap.DeviceNamespace}
	for _, service := range services.Service {
		if service.Namespace == ioNamespace {
			if _, err := r.soap.Resolve(service.XAddr); err != nil {
				return relayInfo{}, err
			}
			info.path, info.namespace = service.XAddr, ioNamespace
			break
		}
	}
	var response struct {
		RelayOutputs []struct {
			Token      string `xml:"token,attr"`
			Properties struct{ Mode, DelayTime string }
		}
	}
	if err := r.soap.Call(ctx, info.path, info.namespace, "GetRelayOutputs", "", &response); err != nil {
		return relayInfo{}, err
	}
	for _, output := range response.RelayOutputs {
		if output.Token != r.token {
			continue
		}
		// The timeout is reported in the ONVIF XML duration vocabulary. Only
		// positive seconds up to five are accepted for this test surface.
		if output.Properties.Mode != "Monostable" {
			return relayInfo{}, ErrUnsupported
		}
		parts := secondsPattern.FindStringSubmatch(output.Properties.DelayTime)
		if len(parts) != 2 {
			return relayInfo{}, ErrUnsupported
		}
		seconds, err := strconv.ParseFloat(parts[1], 64)
		if err != nil || seconds < 0.1 || seconds > 5 {
			return relayInfo{}, ErrUnsupported
		}
		info.delay = time.Duration(seconds * float64(time.Second))
		return info, nil
	}
	return relayInfo{}, ErrUnsupported
}

// Pulse activates the already configured monostable relay once, then explicitly
// deactivates it after its advertised delay or cancellation. The source's own
// timer bounds activation even if the translator loses power.
func (r *Relay) Pulse(ctx context.Context) (result error) {
	info, err := r.discover(ctx)
	if err != nil {
		return err
	}
	set := func(ctx context.Context, state string) error {
		return r.soap.Call(ctx, info.path, info.namespace, "SetRelayOutputState", "<t:RelayOutputToken>"+onvifsoap.Text(r.token)+"</t:RelayOutputToken><t:LogicalState>"+state+"</t:LogicalState>", nil)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := set(cleanup, "inactive"); err != nil {
			result = errors.Join(result, errors.New("relay deactivation failed"))
		}
	}()
	if err := set(ctx, "active"); err != nil {
		return err
	}
	timer := time.NewTimer(info.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
