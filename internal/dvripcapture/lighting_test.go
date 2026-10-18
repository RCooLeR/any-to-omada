package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/capture"
)

func TestLightingPulseRestoresSelectedLens(t *testing.T) {
	device, done := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		var table []any
		if err := json.Unmarshal([]byte(`[[{"LightType":"InfraredLight","Mode":"Auto","PercentOfMaxBrightness":70},{"LightType":"WhiteLight","Mode":"Auto","PercentOfMaxBrightness":30,"Sensitive":3}],[{"LightType":"WhiteLight","Mode":"Auto","PercentOfMaxBrightness":20}]]`), &table); err != nil {
			return err
		}
		for i, method := range []string{"configManager.getConfig", "configManager.setConfig", "configManager.getConfig", "configManager.setConfig", "global.logout"} {
			request, err := p.request(method)
			if err != nil {
				return err
			}
			params := map[string]any{}
			if method != "global.logout" {
				fields, _ := request["params"].(map[string]any)
				if fields["channel"] != json.Number("1") {
					return errors.New("request did not pin selected source channel")
				}
				if method == "configManager.setConfig" {
					options, ok := fields["options"].([]any)
					if !ok || len(options) != 0 {
						return errors.New("write omitted empty options contract")
					}
				}
			}
			if method == "configManager.getConfig" {
				if i == 2 {
					table[1].([]any)[0].(map[string]any)["Sensitive"] = 9
				}
				params["table"] = table
			} else if method == "configManager.setConfig" {
				fields, _ := request["params"].(map[string]any)
				if fields["name"] != "Lighting_V2" {
					return errors.New("unexpected config name")
				}
				table, _ = fields["table"].([]any)
				white, err := whiteLightEntry(table, 0)
				if err != nil {
					return err
				}
				wantMode, wantBrightness := "Manual", 50
				if i == 3 {
					wantMode, wantBrightness = "Auto", 30
				}
				if white["Mode"] != wantMode || !sameBrightness(white["PercentOfMaxBrightness"], wantBrightness) || white["Sensitive"] != json.Number("3") {
					return fmt.Errorf("incorrect selected light write %d", i)
				}
				if i == 3 && table[1].([]any)[0].(map[string]any)["Sensitive"] != json.Number("9") {
					return errors.New("restore overwrote other profile")
				}
			}
			if err := p.reply(request, params, ""); err != nil {
				return err
			}
		}
		return nil
	})
	err := NewLighting(device).Pulse(t.Context(), 1, 0, 50, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("pulse restoration: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLightingPartialReplyUsesFreshSessionForRestoration(t *testing.T) {
	for _, reconnect := range []bool{true, false} {
		t.Run(fmt.Sprintf("reconnect_%t", reconnect), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				var table []any
				_ = json.Unmarshal([]byte(`[[{"LightType":"WhiteLight","Mode":"Auto","PercentOfMaxBrightness":30}]]`), &table)
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				p := fakePeer{conn}
				defer p.Close()
				_ = p.SetDeadline(time.Now().Add(5 * time.Second))
				if err = p.login(true); err != nil {
					done <- err
					return
				}
				read, err := p.request("configManager.getConfig")
				if err != nil {
					done <- err
					return
				}
				if err = p.reply(read, map[string]any{"table": table}, ""); err != nil {
					done <- err
					return
				}
				write, err := p.request("configManager.setConfig")
				if err != nil {
					done <- err
					return
				}
				table = write["params"].(map[string]any)["table"].([]any)
				// The camera applied the activation but delivered only half of a
				// response header. Reusing this socket would lose frame alignment.
				if _, err = p.Write(make([]byte, 16)); err != nil {
					done <- err
					return
				}
				if !reconnect {
					_ = listener.Close()
				}
				cancel()
				if !reconnect {
					done <- nil
					return
				}
				fresh, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				q := fakePeer{fresh}
				defer q.Close()
				_ = q.SetDeadline(time.Now().Add(5 * time.Second))
				if err = q.login(true); err != nil {
					done <- err
					return
				}
				read, err = q.request("configManager.getConfig")
				if err != nil {
					done <- err
					return
				}
				if err = q.reply(read, map[string]any{"table": table}, ""); err != nil {
					done <- err
					return
				}
				write, err = q.request("configManager.setConfig")
				if err != nil {
					done <- err
					return
				}
				entry, err := whiteLightEntry(write["params"].(map[string]any)["table"].([]any), 0)
				if err != nil || entry["Mode"] != "Auto" || !sameBrightness(entry["PercentOfMaxBrightness"], 30) {
					done <- errors.New("fresh session did not restore")
					return
				}
				if err = q.reply(write, nil, ""); err != nil {
					done <- err
					return
				}
				logout, err := q.request("global.logout")
				if err != nil {
					done <- err
					return
				}
				done <- q.reply(logout, nil, "")
			}()
			device := capture.Device{Host: "127.0.0.1", NativePort: listener.Addr().(*net.TCPAddr).Port, Username: "viewer", Password: "example-only"}
			err = NewLighting(device).Pulse(ctx, 0, 0, 50, time.Second)
			if err == nil {
				t.Fatal("uncertain activation incorrectly returned success")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWhiteLightEntryRejectsMissingOrAmbiguousLens(t *testing.T) {
	entry := map[string]any{"LightType": "WhiteLight", "Mode": "Auto", "PercentOfMaxBrightness": 50}
	for _, table := range [][]any{nil, {[]any{}}, {[]any{entry, entry}}, {[]any{map[string]any{"LightType": "WhiteLight"}}}, {[]any{[]any{entry}}}} {
		if _, err := whiteLightEntry(table, 0); !errors.Is(err, ErrLightingUnsupported) {
			t.Fatal("unsupported table accepted")
		}
	}
	table := []any{[]any{entry}}
	got, err := whiteLightEntry(table, 0)
	if err != nil || !reflect.DeepEqual(got, entry) {
		t.Fatal("valid light rejected")
	}
	if _, err := whiteLightEntry(table, 1); err == nil {
		t.Fatal("absent lens accepted")
	}
}

func TestLightingReadOnlyProbeDoesNotWrite(t *testing.T) {
	device, done := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		request, err := p.request("configManager.getConfig")
		if err != nil {
			return err
		}
		if err := p.reply(request, map[string]any{"table": []any{[]any{[]any{map[string]any{"LightType": "InfraredLight"}}}}}, ""); err != nil {
			return err
		}
		request, err = p.request("global.logout")
		if err != nil {
			return err
		}
		return p.reply(request, nil, "")
	})
	if err := NewLighting(device).Available(t.Context(), 0, 0); !errors.Is(err, ErrLightingUnsupported) {
		t.Fatal("IR-only camera offered white light")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLightingSettingsReadsNumericEquivalentBrightness(t *testing.T) {
	for _, encoded := range []string{"50", "50.0", "5e1"} {
		t.Run(encoded, func(t *testing.T) {
			device, done := startFake(t, func(p fakePeer) error {
				if err := p.login(true); err != nil {
					return err
				}
				request, err := p.request("configManager.getConfig")
				if err != nil {
					return err
				}
				var table []any
				decoder := json.NewDecoder(strings.NewReader(`[[{"LightType":"WhiteLight","Mode":"Auto","PercentOfMaxBrightness":` + encoded + `}]]`))
				decoder.UseNumber()
				if err := decoder.Decode(&table); err != nil {
					return err
				}
				if err := p.reply(request, map[string]any{"table": table}, ""); err != nil {
					return err
				}
				request, err = p.request("global.logout")
				if err != nil {
					return err
				}
				return p.reply(request, nil, "")
			})
			settings, err := NewLighting(device).Settings(t.Context(), 0, 0)
			if err != nil || settings != (LightingSettings{Mode: "Auto", Brightness: 50}) {
				t.Fatalf("settings: %+v %v", settings, err)
			}
			if !sameBrightness(json.Number(encoded), 50) {
				t.Fatal("equivalent brightness blocked restoration")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLightingReadRejectsMismatchedEchoedChannel(t *testing.T) {
	call := func(context.Context, string, any) (map[string]any, error) {
		return map[string]any{"params": map[string]any{"channel": json.Number("1"), "table": []any{[]any{map[string]any{"LightType": "WhiteLight", "Mode": "Auto", "PercentOfMaxBrightness": json.Number("50")}}}}}, nil
	}
	if _, err := lightingTable(t.Context(), call, 0); !errors.Is(err, ErrLightingUnsupported) {
		t.Fatal("cross-channel response accepted")
	}
	if _, err := lightingTable(t.Context(), call, 1); err != nil {
		t.Fatal("matching channel response refused")
	}
}
