// Package capture defines the shared adapter and structured-log contracts.
package capture

import (
	"errors"
	"net"
	"net/url"
	"strconv"
)

var ErrAuthentication = errors.New("camera authentication rejected")
var ErrLimit = errors.New("capture storage limit reached")

type Device struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Brand       string `json:"brand"`
	Username    string `json:"-"`
	Password    string `json:"-"`
	HTTPPort    int    `json:"http_port"`
	NativePort  int    `json:"native_port"`
	ONVIFPath   string `json:"onvif_path"`
	Scheme      string `json:"scheme"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func (d Device) Origin() string {
	scheme := d.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := d.HTTPPort
	if port == 0 {
		port = 80
		if scheme == "https" {
			port = 443
		}
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(d.Host, strconv.Itoa(port))}).String()
}

// Sink receives semantic payloads; its implementation redacts secrets centrally.
type Sink interface {
	Write(deviceID, protocol, kind string, data any) error
}
