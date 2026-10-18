package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

// lightingModeFixture serves selected native config tables and addressed writes
// over the real session framing, without a physical camera.
type lightingModeFixture struct {
	white, infrared, scheme string
	brightness              any
	product                 map[string]any
	profileMode             int
	writes                  []string
	loseWrite               int
	foreignMode             bool
	afterLogout             func()
	stallReadback           bool
}

// newLightingModeFixture supplies measured-capability shapes with dummy values.
func newLightingModeFixture() *lightingModeFixture {
	return &lightingModeFixture{white: "Auto", infrared: "Auto", scheme: "AIMode", brightness: 35,
		product: map[string]any{"LightingControl": map[string]any{"Support": true, "LightTypeComplex": []any{"InfraredLight", "WhiteLight"},
			"ModesComplex":     map[string]any{"WhiteLight": []any{"Manual", "Auto", "Off"}, "InfraredLight": []any{"Manual", "Auto", "Off"}},
			"MixLightSolution": map[string]any{"LightingScheme": []any{"WhiteMode", "InfraredMode", "AIMode"}}}}}
}

// serve answers one native control session and optionally drops a write reply.
func (f *lightingModeFixture) serve(p fakePeer) error {
	if err := p.login(true); err != nil {
		return err
	}
	for {
		frame, err := readFrame(p)
		if err != nil {
			return err
		}
		messages, err := jsonMessages(frame.body)
		if err != nil || len(messages) != 1 {
			return errors.New("invalid lighting fixture request")
		}
		request := messages[0]
		params, _ := request["params"].(map[string]any)
		answer := map[string]any{}
		switch request["method"] {
		case "magicBox.getProductDefinition":
			answer["definition"] = f.product
		case "configManager.getConfig":
			if f.stallReadback && len(f.writes) == 2 {
				f.stallReadback = false
				// Withhold post-activation readback until the pulse deadline
				// closes this session, then accept independent restoration.
				if _, err := readFrame(p); err == nil {
					return errors.New("stalled readback session was not canceled")
				}
				return nil
			}
			switch params["name"] {
			case "VideoInMode":
				if params["channel"] != json.Number("0") {
					return errors.New("profile read did not select verified source channel")
				}
				answer["table"] = map[string]any{"Mode": f.profileMode, "Config": []any{0}}
			case "Lighting_V2":
				if _, present := params["channel"]; present {
					return errors.New("lighting read must use whole-device native contract")
				}
				answer["table"] = []any{[]any{[]any{
					map[string]any{"LightType": "InfraredLight", "Mode": f.infrared},
					map[string]any{"LightType": "WhiteLight", "Mode": f.white, "PercentOfMaxBrightness": 100, "NearLight": []any{map[string]any{"Light": f.brightness, "Angle": 50}}},
				}, []any{map[string]any{"LightType": "WhiteLight", "Mode": "Off", "PercentOfMaxBrightness": 70, "NearLight": []any{map[string]any{"Light": 70}}}}}, []any{map[string]any{"UnrelatedChannel": true}}}
			case "LightingScheme":
				answer["table"] = []any{[]any{map[string]any{"LightingMode": f.scheme}, map[string]any{"LightingMode": "InfraredMode"}}, []any{map[string]any{"UnrelatedChannel": true}}}
			default:
				return errors.New("unexpected config read")
			}
		case "configManager.setConfig":
			name, _ := params["name"].(string)
			options, ok := params["options"].([]any)
			if !ok || len(options) != 0 {
				return errors.New("field write omitted options contract")
			}
			f.writes = append(f.writes, name)
			full, ok := params["table"].([]any)
			if !ok || len(full) != 2 || !reflect.DeepEqual(full[1], []any{map[string]any{"UnrelatedChannel": true}}) {
				return errors.New("whole-device table omitted or changed unrelated channel")
			}
			profiles, ok := full[0].([]any)
			if !ok || len(profiles) != 2 {
				return errors.New("source profiles lost")
			}
			if _, present := params["channel"]; present {
				return errors.New("write incorrectly combined channel with whole table")
			}
			switch name {
			case "Lighting_V2":
				if profiles[1].([]any)[0].(map[string]any)["Mode"] != "Off" || profiles[1].([]any)[0].(map[string]any)["PercentOfMaxBrightness"] != json.Number("70") {
					return errors.New("unrelated profile changed")
				}
				entries := profiles[0].([]any)
				white := entries[1].(map[string]any)
				bank := white["NearLight"].([]any)[0].(map[string]any)
				if bank["Angle"] != json.Number("50") || white["PercentOfMaxBrightness"] != json.Number("100") {
					return errors.New("unrelated light fields changed")
				}
				f.brightness = bank["Light"]
				f.white = white["Mode"].(string)
				f.infrared = entries[0].(map[string]any)["Mode"].(string)
			case "LightingScheme":
				if profiles[1].(map[string]any)["LightingMode"] != "InfraredMode" {
					return errors.New("unrelated scheme profile changed")
				}
				f.scheme = profiles[0].(map[string]any)["LightingMode"].(string)
			default:
				return errors.New("write used an unsupported indexed native config name")
			}
			if f.loseWrite == len(f.writes) {
				return nil // The server closes after applying, before acknowledgment.
			}
		case "global.logout":
			if f.foreignMode && len(f.writes) == 2 {
				f.white = "Off"
			}
			if f.afterLogout != nil {
				f.afterLogout()
				f.afterLogout = nil
			}
			return p.reply(request, nil, "")
		default:
			return errors.New("unexpected lighting method")
		}
		if err := p.reply(request, answer, ""); err != nil {
			return err
		}
	}
}

// startLightingModeFixture accepts the activation and explicitly expected
// restoration sessions, retaining all state only in the test process.
func startLightingModeFixture(t *testing.T, f *lightingModeFixture, sessions int) (*Lighting, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		for i := 0; i < sessions; i++ {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				conn.Close()
				done <- err
				return
			}
			err = f.serve(fakePeer{conn})
			conn.Close()
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	device := capture.Device{Host: "127.0.0.1", NativePort: listener.Addr().(*net.TCPAddr).Port, Username: "viewer", Password: "example-only"}
	return NewLighting(device), done
}

func TestPersistentWhiteModePreservesOtherChannelsAndProfiles(t *testing.T) {
	f := newLightingModeFixture()
	l, done := startLightingModeFixture(t, f, 1)
	if err := l.SetMode(t.Context(), 0, 0, "WhiteMode", "Manual", 60); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.white != "Manual" || f.scheme != "WhiteMode" || !sameBrightness(f.brightness, 60) {
		t.Fatal("persistent setting was not applied and retained")
	}
	want := []string{"Lighting_V2", "LightingScheme"}
	if !reflect.DeepEqual(f.writes, want) {
		t.Fatalf("wrong source field contract: %v", f.writes)
	}
}

func TestWhiteModeRequiresRealCapabilityAndFixedActiveProfile(t *testing.T) {
	for _, kind := range []string{"generic_table_only", "no_manual", "scheduled_profile"} {
		t.Run(kind, func(t *testing.T) {
			f := newLightingModeFixture()
			switch kind {
			case "generic_table_only":
				f.product = map[string]any{}
			case "no_manual":
				f.product["LightingControl"].(map[string]any)["ModesComplex"] = map[string]any{"WhiteLight": []any{"Auto"}}
			case "scheduled_profile":
				f.profileMode = 1
			}
			l, done := startLightingModeFixture(t, f, 1)
			if err := l.SetMode(t.Context(), 0, 0, "WhiteMode", "Manual", 60); !errors.Is(err, ErrLightingUnsupported) {
				t.Fatalf("unsupported camera settings accepted: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if len(f.writes) != 0 {
				t.Fatal("unsupported source received a write")
			}
		})
	}
}

func TestWhiteLeaseRestoresConfigurationAfterUncertainWrite(t *testing.T) {
	f := newLightingModeFixture()
	f.loseWrite = 2
	l, done := startLightingModeFixture(t, f, 2)
	lease, err := l.Acquire(t.Context(), 0, 0, 60)
	if err == nil || lease == nil {
		t.Fatal("uncertain activation was reported successful or lost cleanup lease")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.white != "Auto" || f.scheme != "AIMode" || !sameBrightness(f.brightness, 35) || len(f.writes) != 4 {
		t.Fatalf("uncertain activation was retried or not restored: %s %s %v %v", f.white, f.scheme, f.brightness, f.writes)
	}
}

func TestWhiteLeaseDoesNotOverwriteForeignChanges(t *testing.T) {
	f := newLightingModeFixture()
	f.foreignMode = true
	l, done := startLightingModeFixture(t, f, 2)
	lease, err := l.Acquire(t.Context(), 0, 0, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Restore(t.Context()); !errors.Is(err, ErrLightingRestore) {
		t.Fatalf("concurrent settings change was not reported: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.white != "Off" || f.scheme != "AIMode" || !sameBrightness(f.brightness, 35) {
		t.Fatal("restoration overwrote another controller or failed to restore owned fields")
	}
}

func TestWhiteBrightnessDoesNotChangeActiveScheme(t *testing.T) {
	f := newLightingModeFixture()
	l, done := startLightingModeFixture(t, f, 1)
	brightness := 73
	if err := l.ApplyMode(t.Context(), 0, 0, LightingChange{WhiteMode: "Manual", Brightness: &brightness}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.scheme != "AIMode" || f.infrared != "Auto" || f.white != "Manual" || !sameBrightness(f.brightness, 73) {
		t.Fatal("white brightness altered unrelated source policy")
	}
	if len(f.writes) != 1 {
		t.Fatal("brightness update wrote unexpected fields")
	}
}

func TestLightingMultiFieldChangeValidatesBeforeWriting(t *testing.T) {
	f := newLightingModeFixture()
	l, done := startLightingModeFixture(t, f, 1)
	brightness := 500
	err := l.ApplyMode(t.Context(), 0, 0, LightingChange{Scheme: "WhiteMode", WhiteMode: "Manual", Brightness: &brightness})
	if !errors.Is(err, ErrLightingUnsupported) {
		t.Fatalf("invalid multi-field operation accepted: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || f.scheme != "AIMode" || f.white != "Auto" {
		t.Fatal("valid first field was applied before invalid brightness rejected")
	}
}

func TestLightingModeReadRejectsWrongSourceChannel(t *testing.T) {
	if _, err := lightingChannelParams(map[string]any{"params": map[string]any{"channel": json.Number("1")}}, 0); !errors.Is(err, ErrLightingUnsupported) {
		t.Fatal("cross-channel configuration accepted")
	}
}

func TestManualWhitePulseRestoresAfterCancellation(t *testing.T) {
	f := newLightingModeFixture()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.afterLogout = cancel
	l, done := startLightingModeFixture(t, f, 2)
	if err := l.ManualPulse(ctx, 0, 0, 20, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("pulse cancellation lost: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.scheme != "AIMode" || f.white != "Auto" || !sameBrightness(f.brightness, 35) {
		t.Fatal("canceled manual pulse left an override behind")
	}
}

func TestManualWhitePulseDeadlineIncludesActivationReadback(t *testing.T) {
	f := newLightingModeFixture()
	f.stallReadback = true
	l, done := startLightingModeFixture(t, f, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err := l.ManualPulse(ctx, 0, 0, 20, 100*time.Millisecond)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("delayed acquisition was not canceled by pulse expiry: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("pulse waited for the outer request timeout before restoration")
	}
	if f.scheme != "AIMode" || f.white != "Auto" || !sameBrightness(f.brightness, 35) || len(f.writes) != 4 {
		t.Fatal("delayed readback extended or retried activation, or prevented restoration")
	}
}
