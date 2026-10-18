// Package capture defines the shared adapter and structured-log contracts.
package capture

import "errors"

// ErrAuthentication means the source camera rejected the adapter's credentials.
var ErrAuthentication = errors.New("camera authentication rejected")

// Device identifies one source endpoint and its in-memory credentials.
type Device struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	Username   string `json:"-"`
	Password   string `json:"-"`
	NativePort int    `json:"native_port"`
}

// Sink receives semantic payloads; its implementation redacts secrets centrally.
type Sink interface {
	Write(deviceID, protocol, kind string, data any) error
}
