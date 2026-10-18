package dvripcapture

import (
	"encoding/json"
	"fmt"
)

// LightingError carries only a fixed operation/stage and optional numeric device
// error code for native controls. It excludes peer fault text and credentials.
type LightingError struct {
	Operation  string `json:"operation"`
	Stage      string `json:"stage"`
	DeviceCode *int64 `json:"device_code,omitempty"`
	cause      error
}

// Error formats the bounded diagnostic fields without peer-supplied text.
func (e *LightingError) Error() string {
	if e.DeviceCode != nil {
		return fmt.Sprintf("native control %s %s (device code %d)", e.Operation, e.Stage, *e.DeviceCode)
	}
	return "native control " + e.Operation + " " + e.Stage
}

// Unwrap preserves classification such as unsupported without leaking its body.
func (e *LightingError) Unwrap() error { return e.cause }

// lightingFailure retains a fixed operation and stage plus an optional unwrap cause, without
// copying native payload text.
func lightingFailure(operation, stage string, cause error) error {
	return &LightingError{Operation: operation, Stage: stage, cause: cause}
}

// lightingRejection classifies a rejected control and retains only a numeric native error code for diagnostics.
func lightingRejection(operation string, answer map[string]any) error {
	failure := &LightingError{Operation: operation, Stage: "rejected", cause: ErrLightingUnsupported}
	value := answer["errCode"]
	if nativeError, ok := answer["error"].(map[string]any); ok {
		value = nativeError["code"]
	}
	if number, ok := value.(json.Number); ok {
		if code, err := number.Int64(); err == nil {
			failure.DeviceCode = &code
		}
	}
	return failure
}
