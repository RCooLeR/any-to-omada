package onvifsoap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResolvePinsEveryAddressForm(t *testing.T) {
	client := New("192.0.2.1", 80, "admin", "test-password", time.Second)
	defer client.Close()
	for _, address := range []string{"/onvif/events?Idx=7", "http://192.0.2.1/onvif/events", "http://192.0.2.1:80/onvif/events"} {
		if _, err := client.Resolve(address); err != nil {
			t.Errorf("same-camera address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{"//192.0.2.2/onvif/events", "//192.0.2.1:8080/onvif/events", "http://192.0.2.2/onvif/events", "http://192.0.2.1:8080/onvif/events", "https://192.0.2.1/onvif/events", "http://admin@example.com/onvif/events"} {
		if _, err := client.Resolve(address); !errors.Is(err, ErrUnavailable) {
			t.Errorf("off-camera address %q accepted: %v", address, err)
		}
	}
}

func TestDoPreservesResponseNamespaceScope(t *testing.T) {
	for _, declaration := range []struct {
		name, envelope, response, parameter string
	}{
		{"prefixed override", ` xmlns:p="urn:outer"`, ` xmlns:p="urn:subscription"`, `<p:SubscriptionId>42</p:SubscriptionId>`},
		{"default namespace", ` xmlns="urn:outer"`, ` xmlns="urn:subscription"`, `<SubscriptionId>42</SubscriptionId>`},
	} {
		t.Run(declaration.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `<s:Envelope xmlns:s="%s" xmlns:e="%s" xmlns:wsa="http://www.w3.org/2005/08/addressing"%s><s:Body><e:CreatePullPointSubscriptionResponse%s><e:SubscriptionReference><wsa:ReferenceParameters>%s</wsa:ReferenceParameters></e:SubscriptionReference></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>`, SOAPNamespace, EventsNamespace, declaration.envelope, declaration.response, declaration.parameter)
			}))
			defer server.Close()
			host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			number, _ := strconv.Atoi(port)
			client := New(host, number, "", "", time.Second)
			defer client.Close()
			var result struct {
				SubscriptionReference struct {
					ReferenceParameters struct {
						Parameters []struct {
							XMLName xml.Name
							Value   string `xml:",chardata"`
						} `xml:",any"`
					}
				}
			}
			if err := client.Call(context.Background(), "/onvif/events", EventsNamespace, "CreatePullPointSubscription", "", &result); err != nil {
				t.Fatal(err)
			}
			parameters := result.SubscriptionReference.ReferenceParameters.Parameters
			if len(parameters) != 1 || parameters[0].XMLName.Space != "urn:subscription" || parameters[0].XMLName.Local != "SubscriptionId" || strings.TrimSpace(parameters[0].Value) != "42" {
				t.Fatalf("reference parameter lost its namespace or value: %v", parameters)
			}
		})
	}
}
