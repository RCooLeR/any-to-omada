package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// deterrenceFixture records native writes and can block or fail activation to
// test acknowledgement ordering and the independent stop cleanup path.
type deterrenceFixture struct {
	mu       sync.Mutex
	caps     map[string]any
	writes   []map[string]any
	activate func(context.Context) error
	stopErr  error
}

// session invokes bounded native operations without network or physical devices.
func (f *deterrenceFixture) session(ctx context.Context, fn func(lightingCall) error) error {
	return fn(func(ctx context.Context, method string, params any) (map[string]any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if method == "CoaxialControlIO.getCaps" {
			return map[string]any{"params": map[string]any{"caps": f.caps}}, nil
		}
		if method != "CoaxialControlIO.control" {
			return nil, errors.New("unexpected native operation")
		}
		command := params.(map[string]any)
		f.mu.Lock()
		f.writes = append(f.writes, command)
		f.mu.Unlock()
		if command["info"].([]any)[0].(map[string]any)["IO"] == 1 {
			if f.activate != nil {
				return nil, f.activate(ctx)
			}
		} else if f.stopErr != nil {
			return nil, f.stopErr
		}
		return map[string]any{"result": true}, nil
	})
}

// controller creates a full-output controller using the isolated fake transport.
func (f *deterrenceFixture) controller() *Deterrence {
	return newDeterrence(DeterrenceConfig{Channel: 2, Light: true, Sound: true, MaxDuration: 2 * time.Second}, f.session)
}

// commands returns a detached write list after synchronizing fixture access.
func (f *deterrenceFixture) commands() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.writes...)
}

func TestDeterrenceRequiresExplicitCapabilities(t *testing.T) {
	for _, caps := range []map[string]any{nil, {}, {"SupportControlLight": json.Number("0"), "SupportControlSpeaker": json.Number("0")}, {"SupportControlLight": true, "SupportControlSpeaker": "On"}} {
		f := &deterrenceFixture{caps: caps}
		c := f.controller()
		if _, err := c.Start(t.Context(), true, true); !errors.Is(err, ErrDeterrenceUnsupported) {
			t.Fatalf("unsupported hardware accepted: %v", err)
		}
		if len(f.commands()) != 0 {
			t.Fatal("unsupported output received a write")
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeterrenceIndependentOutputContractAndStop(t *testing.T) {
	f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "0", "SupportControlSpeaker": json.Number("1")}}
	c := f.controller()
	defer c.Close()
	if duration, err := c.Start(t.Context(), false, true); err != nil || duration != 2*time.Second {
		t.Fatalf("sound start: %v %v", duration, err)
	}
	if c.Status() != (DeterrenceStatus{Active: true, Sound: true}) {
		t.Fatalf("acknowledged state: %+v", c.Status())
	}
	if _, err := c.Start(t.Context(), false, true); !errors.Is(err, ErrDeterrenceBusy) {
		t.Fatal("overlapping start accepted")
	}
	if err := c.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"channel": 2, "info": []any{map[string]any{"Type": 2, "IO": 1, "TriggerMode": 2}}},
		{"channel": 2, "info": []any{map[string]any{"Type": 2, "IO": 2, "TriggerMode": 2}}},
	}
	if !reflect.DeepEqual(f.commands(), want) {
		t.Fatalf("native contract: %#v", f.commands())
	}
	if c.Status() != (DeterrenceStatus{}) {
		t.Fatal("acknowledged stop retained active state")
	}
}

func TestDeterrenceStopCancelsPendingStart(t *testing.T) {
	activated := make(chan struct{})
	f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "1", "SupportControlSpeaker": "1"}}
	f.activate = func(ctx context.Context) error {
		close(activated)
		<-ctx.Done()
		return ctx.Err()
	}
	c := f.controller()
	defer c.Close()
	started := make(chan error, 1)
	go func() {
		_, err := c.Start(t.Context(), true, true)
		started <- err
	}()
	<-activated
	if !c.Status().Unconfirmed || c.Status().Active {
		t.Fatal("unacknowledged activation reported success")
	}
	if err := c.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("start cancellation lost: %v", err)
	}
	if writes := f.commands(); len(writes) != 2 {
		t.Fatalf("start must not retry; bounded cleanup once: %d writes", len(writes))
	}
	if c.Status() != (DeterrenceStatus{}) {
		t.Fatal("cleanup did not confirm stop")
	}
}

func TestDeterrenceWatchdogAndCloseStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "1", "SupportControlSpeaker": "1"}}
		c := f.controller()
		if _, err := c.Start(t.Context(), true, false); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if c.Status().Active || len(f.commands()) != 2 {
			t.Fatal("watchdog did not stop acknowledged activation")
		}
		if _, err := c.Start(t.Context(), false, true); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if c.Status() != (DeterrenceStatus{}) || len(f.commands()) != 4 {
			t.Fatal("shutdown failed to stop and join")
		}
		if _, err := c.Start(t.Context(), true, false); !errors.Is(err, ErrDeterrenceUnavailable) {
			t.Fatal("closed controller accepted a start")
		}
	})
}

func TestDeterrenceStopFailureRetainsUncertainState(t *testing.T) {
	f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "1"}, stopErr: errors.New("test stop failure")}
	c := f.controller()
	defer c.Close()
	if _, err := c.Start(t.Context(), true, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(t.Context()); !errors.Is(err, ErrDeterrenceStop) {
		t.Fatalf("stop failure hidden: %v", err)
	}
	if state := c.Status(); !state.Unconfirmed || !state.Light {
		t.Fatalf("unknown final state lost: %+v", state)
	}
	if _, err := c.Start(t.Context(), true, false); !errors.Is(err, ErrDeterrenceBusy) {
		t.Fatal("start accepted while previous shutdown unresolved")
	}
}

func TestDeterrenceStaleDeadlineCannotStopLaterActivation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "1"}}
		c := f.controller()
		defer c.Close()
		if _, err := c.Start(t.Context(), true, false); err != nil {
			t.Fatal(err)
		}
		previous := c.expires
		if err := c.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
		if _, err := c.Start(t.Context(), true, false); err != nil {
			t.Fatal(err)
		}
		if err := c.stopExpired(t.Context(), previous); err != nil {
			t.Fatal(err)
		}
		if !c.Status().Active || len(f.commands()) != 3 {
			t.Fatal("stale deadline stopped a later activation")
		}
	})
}

func TestDeterrenceWatchdogStartsAtActivationAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &deterrenceFixture{caps: map[string]any{"SupportControlLight": "1"}}
		f.activate = func(ctx context.Context) error {
			select {
			case <-time.After(4 * time.Second):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		c := f.controller()
		defer c.Close()
		started := time.Now()
		if _, err := c.Start(t.Context(), true, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("delayed activation acknowledgment exceeded its lease: %v", err)
		}
		if time.Since(started) != 2*time.Second || len(f.commands()) != 2 || c.Status().Active {
			t.Fatal("response latency extended the configured alarm deadline")
		}
	})
}
