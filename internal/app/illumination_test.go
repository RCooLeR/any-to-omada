package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
)

// illuminationFake records whole validated transactions without hardware writes.
type illuminationFake struct {
	mu      sync.Mutex
	current dvripcapture.LightingModeSettings
	changes []dvripcapture.LightingChange
	apply   func() error
	read    func(context.Context) (dvripcapture.LightingModeSettings, error)
	reads   int
}

// ModeSettings returns the source fixture's current lighting policy and bank.
func (f *illuminationFake) ModeSettings(ctx context.Context, _, _ int) (dvripcapture.LightingModeSettings, error) {
	f.mu.Lock()
	f.reads++
	current, read := f.current, f.read
	f.mu.Unlock()
	if read != nil {
		return read(ctx)
	}
	return current, nil
}

// readCount synchronizes observations with later periodic refresh attempts.
func (f *illuminationFake) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// ApplyMode records only requests that passed complete adapter validation.
func (f *illuminationFake) ApplyMode(_ context.Context, _, _ int, c dvripcapture.LightingChange) error {
	f.mu.Lock()
	f.changes = append(f.changes, c)
	apply := f.apply
	f.mu.Unlock()
	if apply != nil {
		return apply()
	}
	return nil
}

// testIllumination owns a real refresh worker with a synthetic source only.
func testIllumination(t *testing.T, f *illuminationFake) *cameraIllumination {
	t.Helper()
	c := newCameraIllumination(t.Context(), &config.WhiteLight{Profile: 0, RecorderModes: []string{"white_led_always_on", "auto_color", "auto_ir", "ir_always_on"}},
		0, f, &sourceControlGate{busy: make(chan struct{}, 1)}, nil)
	c.Start()
	t.Cleanup(c.Close)
	return c
}

func TestIlluminationIdleWorkerWaitsForValidationAndParentCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		f := &illuminationFake{}
		c := newCameraIllumination(ctx, &config.WhiteLight{}, 0, f, &sourceControlGate{busy: make(chan struct{}, 1)}, nil)
		defer c.Close()
		synctest.Wait()
		if f.readCount() != 0 {
			t.Fatal("idle worker contacted a source before startup validation")
		}
		cancel()
		<-c.done
		if f.readCount() != 0 {
			t.Fatal("parent cancellation started source traffic")
		}
	})
}

func TestIlluminationShutdownJoinsRollbackAndRetainsUncertainty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		restore := make(chan struct{})
		f := &illuminationFake{apply: func() error {
			<-restore
			return errors.Join(dvripcapture.ErrLightingRestore, errors.New("private source failure"))
		}}
		c := testIllumination(t, f)
		synctest.Wait()
		setDone := make(chan struct{})
		go func() {
			defer close(setDone)
			_ = c.Set(t.Context(), omadafront.IlluminationChange{Mode: "white_led_always_on"})
		}()
		synctest.Wait()
		closed := make(chan struct{})
		go func() { c.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("shutdown returned before rollback finished")
		default:
		}
		if c.Set(t.Context(), omadafront.IlluminationChange{Mode: "white_led_always_on"}) == nil {
			t.Fatal("shutdown admitted another persistent write")
		}
		close(restore)
		<-setDone
		<-closed
		if !c.Status().RestorationUnconfirmed {
			t.Fatal("failed persistent restoration was forgotten")
		}
	})
}

func TestIlluminationPreservesUnknownPolicyAndIndependentWhiteBrightness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &illuminationFake{current: dvripcapture.LightingModeSettings{Scheme: "AIMode", WhiteMode: "Auto", InfraredMode: "Auto", Brightness: 50}}
		c := testIllumination(t, f)
		synctest.Wait()
		current, err := c.Settings(t.Context())
		if err != nil || current.Mode != "" || current.Brightness != 50 || !current.AutomaticBrightness {
			t.Fatal("unknown source policy fabricated or brightness lost")
		}
		brightness := 30
		if err := c.Set(t.Context(), omadafront.IlluminationChange{Brightness: &brightness}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !reflect.DeepEqual(f.changes, []dvripcapture.LightingChange{{Brightness: &brightness}}) {
			t.Fatal("white brightness silently switched lighting scheme")
		}
		if err := c.Set(t.Context(), omadafront.IlluminationChange{Mode: "auto_ir", Brightness: &brightness}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		change := f.changes[1]
		if change.Scheme != "InfraredMode" || change.InfraredMode != "Auto" || change.WhiteMode != "" || change.Brightness != &brightness {
			t.Fatal("infrared policy overwrote white lamp mode")
		}
		automatic := true
		if err := c.Set(t.Context(), omadafront.IlluminationChange{Mode: "white_led_always_on", AutomaticBrightness: &automatic}); err == nil || len(f.changes) != 2 {
			t.Fatal("conflicting persistent policy reached source")
		}
		if err := c.Set(t.Context(), omadafront.IlluminationChange{Mode: "off"}); err == nil || len(f.changes) != 2 {
			t.Fatal("unsupported persistent mode reached source")
		}
	})
}

func TestIlluminationBlockedSourceCannotDelayRecorderReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &illuminationFake{read: func(ctx context.Context) (dvripcapture.LightingModeSettings, error) {
			<-ctx.Done()
			return dvripcapture.LightingModeSettings{}, ctx.Err()
		}}
		c := testIllumination(t, f)
		synctest.Wait()
		front, err := omadafront.New(omadafront.Config{Username: "test", Password: "synthetic-only", IP: "192.0.2.1", Illumination: c})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		for range 10 {
			response := front.Passthrough([]byte(`{"method":"get","image":{"name":["switch","common","switch"]},"network":{"name":"wan_status"}}`))
			var value map[string]any
			if err := json.Unmarshal(response, &value); err != nil {
				t.Fatal(err)
			}
			image, _ := value["image"].(map[string]any)
			fields, _ := image["switch"].(map[string]any)
			if value["network"] == nil || len(image) != 1 || len(fields) != 1 || fields["flicker"] != "50hz" {
				t.Fatalf("cold source lost independent state or fabricated physical lighting: %s", response)
			}
		}
		if time.Since(started) != 0 || f.readCount() != 1 {
			t.Fatal("recorder reads waited for or repeated source I/O")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.Settings(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("passive settings ignored request cancellation")
		}
		c.Close()
		if time.Since(started) != 0 {
			t.Fatal("shutdown did not cancel the blocked snapshot refresh")
		}
	})
}

func TestIlluminationSnapshotsExpireAndFailuresDiscardThem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &illuminationFake{current: dvripcapture.LightingModeSettings{Scheme: "WhiteMode", WhiteMode: "Manual", Brightness: 40}}
		c := testIllumination(t, f)
		synctest.Wait()
		if snapshot, err := c.Settings(t.Context()); err != nil || snapshot.Brightness != 40 {
			t.Fatal("initial refresh did not publish validated settings")
		}
		f.mu.Lock()
		f.read = func(context.Context) (dvripcapture.LightingModeSettings, error) {
			return dvripcapture.LightingModeSettings{}, errors.New("source failed")
		}
		f.mu.Unlock()
		c.requestRefresh()
		synctest.Wait()
		if _, err := c.Settings(t.Context()); !errors.Is(err, errIlluminationSnapshotUnavailable) {
			t.Fatal("failed refresh retained stale settings")
		}
		f.mu.Lock()
		f.read = nil
		f.mu.Unlock()
		c.requestRefresh()
		synctest.Wait()
		c.gate.busy <- struct{}{}
		time.Sleep(illuminationSnapshotLifetime)
		synctest.Wait()
		if _, err := c.Settings(t.Context()); !errors.Is(err, errIlluminationSnapshotUnavailable) {
			t.Fatal("expired settings were reported as current")
		}
		<-c.gate.busy
	})
}

func TestIlluminationWriteInvalidatesUntilFreshReadback(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := &illuminationFake{current: dvripcapture.LightingModeSettings{Scheme: "WhiteMode", WhiteMode: "Manual", Brightness: 40}}
				c := testIllumination(t, f)
				synctest.Wait()
				f.mu.Lock()
				f.read = func(ctx context.Context) (dvripcapture.LightingModeSettings, error) {
					<-ctx.Done()
					return dvripcapture.LightingModeSettings{}, ctx.Err()
				}
				if failed {
					f.apply = func() error { return dvripcapture.ErrLightingRestore }
				}
				f.mu.Unlock()
				brightness := 60
				err := c.Set(t.Context(), omadafront.IlluminationChange{Brightness: &brightness})
				if (err != nil) != failed {
					t.Fatal("unexpected persistent write result")
				}
				synctest.Wait()
				if _, err := c.Settings(t.Context()); !errors.Is(err, errIlluminationSnapshotUnavailable) {
					t.Fatal("write retained stale pre-write settings")
				}
				if c.Status().RestorationUnconfirmed != failed {
					t.Fatal("snapshot refresh changed restoration uncertainty")
				}
				if f.readCount() != 2 {
					t.Fatal("write did not request one immediate refresh")
				}
			})
		})
	}
}

func TestIlluminationRefreshBoundAndAuthenticationCooldown(t *testing.T) {
	t.Run("read_timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var completed atomic.Int32
			f := &illuminationFake{read: func(ctx context.Context) (dvripcapture.LightingModeSettings, error) {
				<-ctx.Done()
				completed.Add(1)
				return dvripcapture.LightingModeSettings{}, ctx.Err()
			}}
			_ = testIllumination(t, f)
			synctest.Wait()
			time.Sleep(illuminationReadTimeout)
			synctest.Wait()
			if completed.Load() != 1 || f.readCount() != 1 {
				t.Fatal("source read exceeded its bound or retried immediately")
			}
			time.Sleep(illuminationRefreshInterval - illuminationReadTimeout)
			synctest.Wait()
			if f.readCount() != 2 {
				t.Fatal("owned worker did not refresh on its interval")
			}
		})
	})
	t.Run("authentication_cooldown", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &illuminationFake{read: func(context.Context) (dvripcapture.LightingModeSettings, error) {
				return dvripcapture.LightingModeSettings{}, capture.ErrAuthentication
			}}
			_ = testIllumination(t, f)
			synctest.Wait()
			time.Sleep(50 * time.Second)
			synctest.Wait()
			if f.readCount() != 1 {
				t.Fatal("periodic refresh bypassed source authentication cooldown")
			}
		})
	})
}
