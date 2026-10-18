package dvripptz

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/onvifptz"
)

// fakeNative records only synthetic protocol requests and injects uncertain
// replies without contacting cameras or waiting for wall-clock watchdogs.
type fakeNative struct {
	mu                                             sync.Mutex
	requests                                       []dvripcapture.ControlRequest
	sessions                                       int
	pan, tilt                                      bool
	authFailure, failStart, failStop, blockFactory bool
	factoryEntered                                 chan struct{}
}

// session models isolated authenticated transports, preserving per-call ordering.
func (f *fakeNative) session(ctx context.Context, _ capture.Device, fn func(dvripcapture.ControlCall) error) error {
	f.mu.Lock()
	f.sessions++
	auth := f.authFailure
	f.mu.Unlock()
	if auth {
		return capture.ErrAuthentication
	}
	return fn(func(ctx context.Context, request dvripcapture.ControlRequest) (map[string]any, error) {
		f.mu.Lock()
		f.requests = append(f.requests, request)
		block, startFailure, stopFailure := f.blockFactory, f.failStart, f.failStop
		f.mu.Unlock()
		switch request.Method {
		case "ptz.factory.instance":
			if block {
				select {
				case f.factoryEntered <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return map[string]any{"result": json.Number("17")}, nil
		case "ptz.getCurrentProtocolCaps":
			return map[string]any{"result": true, "params": map[string]any{"caps": map[string]any{"Pan": f.pan, "Tile": f.tilt, "PanSpeedMin": json.Number("1"), "PanSpeedMax": json.Number("255"), "TileSpeedMin": json.Number("1"), "TileSpeedMax": json.Number("255")}}}, nil
		case "ptz.start":
			if startFailure {
				return nil, errors.New("synthetic uncertain start")
			}
		case "ptz.stop":
			if stopFailure {
				return nil, errors.New("synthetic uncertain stop")
			}
		default:
			return nil, errors.New("unexpected method")
		}
		return map[string]any{"result": true}, nil
	})
}

// movements returns a detached slice of start/stop calls for protocol assertions.
func (f *fakeNative) movements() []dvripcapture.ControlRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []dvripcapture.ControlRequest
	for _, request := range f.requests {
		if request.Method == "ptz.start" || request.Method == "ptz.stop" {
			result = append(result, request)
		}
	}
	return result
}

// testController injects an in-memory transport before any work is submitted.
func testController(t *testing.T, fake *fakeNative) *Controller {
	t.Helper()
	c, err := New(Config{Device: capture.Device{Host: "192.0.2.10", Username: "test", Password: "synthetic"}, Channel: 0, MaxMove: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.session = fake.session
	t.Cleanup(c.Close)
	return c
}

func TestNativeCapabilityRequiresBothAxesAndOmitsOptionalControls(t *testing.T) {
	for _, axes := range [][2]bool{{true, true}, {true, false}, {false, true}, {false, false}} {
		fake := &fakeNative{pan: axes[0], tilt: axes[1]}
		c := testController(t, fake)
		got, err := c.Capability(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		want := onvifptz.Capability{PanTilt: axes[0] && axes[1]}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if _, err := c.Presets(t.Context()); !errors.Is(err, onvifptz.ErrUnsupported) {
			t.Fatalf("preset list error: %v", err)
		}
		if len(fake.movements()) != 0 {
			t.Fatal("discovery sent physical commands")
		}
	}
}

func TestNativeMoveStopUsesCapturedFactoryArguments(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true}
		c := testController(t, fake)
		c.Move(.5, 1, 0)
		synctest.Wait()
		c.Stop()
		synctest.Wait()
		requests := fake.movements()
		if len(requests) != 2 {
			t.Fatalf("movement count %d", len(requests))
		}
		want := nativeMove{Code: "RightUp", Arg1: 8, Arg2: 8, Channel: 0}
		for i, request := range requests {
			if request.Params != want || request.Object != 17 || request.Sequence != uint32(i+1) || !request.SessionSequence {
				t.Fatalf("request %d mismatch: %+v", i, request)
			}
		}
		if requests[0].Method != "ptz.start" || requests[1].Method != "ptz.stop" {
			t.Fatal("start/stop order incorrect")
		}
		if status := c.Status(); status.Moving || status.Moves != 1 || status.Stops != 1 {
			t.Fatalf("status %+v", status)
		}
	})
}

func TestNativeWatchdogAndCloseStopAcknowledgedMovement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true}
		c := testController(t, fake)
		c.Move(-1, 0, 0)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if status := c.Status(); status.Moving || status.WatchdogStops != 1 || status.Stops != 1 {
			t.Fatalf("watchdog status %+v", status)
		}
		c.Move(0, -1, 0)
		synctest.Wait()
		c.Close()
		if c.Status().Moving {
			t.Fatal("close did not acknowledge stop")
		}
	})
}

func TestNativeReplacementStopsBeforeNextStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		synctest.Wait()
		c.Move(0, 1, 0)
		synctest.Wait()
		c.Stop()
		synctest.Wait()
		var got []string
		for _, request := range fake.movements() {
			got = append(got, request.Method+":"+request.Params.(nativeMove).Code)
		}
		want := []string{"ptz.start:Right", "ptz.stop:Right", "ptz.start:Up", "ptz.stop:Up"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func TestNativeStopDuringDiscoveryNeverStarts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true, blockFactory: true, factoryEntered: make(chan struct{}, 1)}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		<-fake.factoryEntered
		c.Stop()
		synctest.Wait()
		if len(fake.movements()) != 0 || c.Status().Moving {
			t.Fatal("stale movement survived stop during discovery")
		}
	})
}

func TestNativeUncertainStartStopsOnFreshSessionWithoutRetryingMove(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true, failStart: true}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		synctest.Wait()
		requests := fake.movements()
		if len(requests) != 2 || requests[0].Method != "ptz.start" || requests[1].Method != "ptz.stop" {
			t.Fatalf("requests %+v", requests)
		}
		if fake.sessions != 2 || c.Status().Moving {
			t.Fatalf("sessions %d, status %+v", fake.sessions, c.Status())
		}
	})
}

func TestNativeFailedStopBlocksReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true, failStop: true}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		synctest.Wait()
		c.Stop()
		synctest.Wait()
		c.Move(-1, 0, 0)
		synctest.Wait()
		starts := 0
		for _, request := range fake.movements() {
			if request.Method == "ptz.start" {
				starts++
			}
		}
		if starts != 1 || !c.Status().Moving {
			t.Fatalf("starts %d, status %+v", starts, c.Status())
		}
	})
}

func TestNativeAuthenticationFailureDoesNotRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{authFailure: true}
		c := testController(t, fake)
		for range 2 {
			if _, err := c.Capability(t.Context()); !errors.Is(err, onvifptz.ErrAuthentication) {
				t.Fatalf("error %v", err)
			}
		}
		c.Move(1, 0, 0)
		synctest.Wait()
		if fake.sessions != 1 {
			t.Fatalf("authentication sessions %d", fake.sessions)
		}
	})
}

func TestNativeDiscoveryCannotInterruptActiveStopCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		synctest.Wait()
		fake.mu.Lock()
		fake.authFailure = true
		fake.mu.Unlock()
		finished := make(chan error, 1)
		go func() { _, err := c.Capability(t.Context()); finished <- err }()
		synctest.Wait()
		if fake.sessions != 1 {
			t.Fatal("discovery started a competing authentication session")
		}
		c.Stop()
		synctest.Wait()
		if err := <-finished; err != nil {
			t.Fatalf("cached capability failed: %v", err)
		}
		if c.Status().Moving || fake.sessions != 1 {
			t.Fatalf("stop status %+v, sessions %d", c.Status(), fake.sessions)
		}
	})
}

func TestNativeUncertainMovementUsesCachedCapabilityWithoutLogin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true, failStop: true}
		c := testController(t, fake)
		c.Move(1, 0, 0)
		synctest.Wait()
		c.Stop()
		synctest.Wait()
		before := fake.sessions
		fake.mu.Lock()
		fake.authFailure = true
		fake.mu.Unlock()
		capability, err := c.Capability(t.Context())
		if err != nil || !capability.PanTilt || fake.sessions != before {
			t.Fatalf("uncertain movement discovery: capability %+v, error %v, sessions %d", capability, err, fake.sessions)
		}
	})
}

func TestNativeDirectionsAndUnsupportedZoom(t *testing.T) {
	for _, test := range []struct {
		pan, tilt float64
		code      string
		arg2      int
	}{{1, 0, "Right", 0}, {-1, 0, "Left", 0}, {0, 1, "Up", 0}, {0, -1, "Down", 0}, {-1, 1, "LeftUp", 8}, {1, -1, "RightDown", 8}} {
		move := direction(test.pan, test.tilt, 3)
		if move == nil || move.Code != test.code || move.Arg2 != test.arg2 || move.Channel != 3 {
			t.Fatalf("direction %+v", move)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeNative{pan: true, tilt: true}
		c := testController(t, fake)
		c.Move(1, 0, 1)
		synctest.Wait()
		if len(fake.movements()) != 0 {
			t.Fatal("unsupported zoom sent movement")
		}
	})
}
