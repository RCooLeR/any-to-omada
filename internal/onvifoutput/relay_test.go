package onvifoutput

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRelayPulseRequiresAdvertisedBoundedMonostableOutput(t *testing.T) {
	for _, tc := range []struct {
		name, mode, delay string
		want              bool
	}{{"monostable", "Monostable", "PT0.1S", true}, {"bistable", "Bistable", "PT0.1S", false}, {"long", "Monostable", "PT60S", false}, {"malformed", "Monostable", "PT1Sjunk", false}, {"missing", "Monostable", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			var states []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				body := string(data)
				op, content, namespace := "GetSystemDateAndTime", "", "http://www.onvif.org/ver10/device/wsdl"
				switch {
				case strings.Contains(body, "GetServices"):
					op = "GetServices"
					content = `<Service><Namespace>` + ioNamespace + `</Namespace><XAddr>http://` + r.Host + `/onvif/io</XAddr></Service>`
				case strings.Contains(body, "GetRelayOutputs"):
					op = "GetRelayOutputs"
					namespace = ioNamespace
					content = `<RelayOutputs token="relay1"><Properties><Mode>` + tc.mode + `</Mode><DelayTime>` + tc.delay + `</DelayTime></Properties></RelayOutputs>`
				case strings.Contains(body, "SetRelayOutputState"):
					op = "SetRelayOutputState"
					namespace = ioNamespace
					if strings.Contains(body, ">active<") {
						states = append(states, "active")
					} else {
						states = append(states, "inactive")
					}
				}
				w.Header().Set("Content-Type", "application/soap+xml")
				fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><t:%sResponse xmlns:t="%s">%s</t:%sResponse></s:Body></s:Envelope>`, op, namespace, content, op)
			}))
			defer server.Close()
			host, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			number, _ := strconv.Atoi(port)
			relay := New(host, number, "fixture", "example-only", "relay1")
			defer relay.Close()
			err := relay.Pulse(context.Background())
			if tc.want {
				if err != nil || strings.Join(states, ",") != "active,inactive" {
					t.Fatalf("pulse result %v %v", err, states)
				}
			} else if err == nil || len(states) != 0 {
				t.Fatalf("unsafe output activated: %v %v", err, states)
			}
		})
	}
}
