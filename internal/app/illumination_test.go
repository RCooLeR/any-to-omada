package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"testing/synctest"

	"github.com/RCooLeR/any-to-omada/internal/config"
	"github.com/RCooLeR/any-to-omada/internal/dvripcapture"
	"github.com/RCooLeR/any-to-omada/internal/omadafront"
)

// illuminationFake records whole validated transactions without hardware writes.
type illuminationFake struct {
	current dvripcapture.LightingModeSettings
	changes []dvripcapture.LightingChange
	apply   func() error
}

// ModeSettings returns the source fixture's current lighting policy and bank.
func (f *illuminationFake) ModeSettings(context.Context, int, int) (dvripcapture.LightingModeSettings, error) {
	return f.current, nil
}

// ApplyMode records only requests that passed complete adapter validation.
func (f *illuminationFake) ApplyMode(_ context.Context, _, _ int, c dvripcapture.LightingChange) error {
	f.changes = append(f.changes, c)
	if f.apply != nil {
		return f.apply()
	}
	return nil
}

func TestIlluminationShutdownJoinsRollbackAndRetainsUncertainty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		restore := make(chan struct{})
		f := &illuminationFake{apply: func() error {
			<-restore
			return errors.Join(dvripcapture.ErrLightingRestore, errors.New("private source failure"))
		}}
		c := &cameraIllumination{cfg: &config.WhiteLight{Profile: 0, RecorderModes: []string{"white_led_always_on"}}, light: f, gate: &sourceControlGate{busy: make(chan struct{}, 1)}}
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
	f := &illuminationFake{current: dvripcapture.LightingModeSettings{Scheme: "AIMode", WhiteMode: "Auto", InfraredMode: "Auto", Brightness: 50}}
	c := &cameraIllumination{cfg: &config.WhiteLight{Profile: 0, RecorderModes: []string{"white_led_always_on", "auto_color", "auto_ir", "ir_always_on"}}, light: f, gate: &sourceControlGate{busy: make(chan struct{}, 1)}}
	current, err := c.Settings(t.Context())
	if err != nil || current.Mode != "" || current.Brightness != 50 || !current.AutomaticBrightness {
		t.Fatal("unknown source policy fabricated or brightness lost")
	}
	brightness := 30
	if err := c.Set(t.Context(), omadafront.IlluminationChange{Brightness: &brightness}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.changes, []dvripcapture.LightingChange{{Brightness: &brightness}}) {
		t.Fatal("white brightness silently switched lighting scheme")
	}
	if err := c.Set(t.Context(), omadafront.IlluminationChange{Mode: "auto_ir", Brightness: &brightness}); err != nil {
		t.Fatal(err)
	}
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
}
