package omadafront

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

// observedEnrollment031Digest fixes the canonical JSON response of the exact
// 0.3.1 build with native callbacks enabled. It contains the public compatibility
// profile only, without source identifiers, credentials or captured private data.
const observedEnrollment031Digest = "b499d7ecdc9d782a27399eec732696030d343213cd2fc838d8e5d2c0c05ede0d"

func TestUnconfiguredOutputsPreserveObservedEnrollmentContract(t *testing.T) {
	for _, mode := range []string{"disabled", "empty", "ptz", "empty illumination"} {
		for _, transport := range []string{"https", "callback"} {
			t.Run(mode+"/"+transport, func(t *testing.T) {
				s := testServer(t, func(cfg *Config) {
					cfg.StartCallback = func(CallbackRequest) error { return nil }
					cfg.Compatibility.ObservedModuleSpec = true
					switch mode {
					case "empty":
						cfg.Outputs = &fakeOutputs{}
					case "ptz":
						cfg.PTZ = &fakePTZ{capability: &PTZCapability{PanTilt: true}}
						cfg.Compatibility.PTZModuleSpecKeys = []string{"ptz"}
					case "empty illumination":
						cfg.Illumination = &fakeIllumination{}
					}
				})
				send := outputTransport(t, s, transport)
				value := send(`{"method":"get","function":{"name":"module_spec"}}`)
				if mode == "ptz" {
					spec := metadataObject(t, metadataObject(t, value["function"])["module_spec"])
					if spec["ptz"] != "1" {
						t.Fatal("configured PTZ offer is missing")
					}
					delete(spec, "ptz")
				}
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != observedEnrollment031Digest {
					t.Fatalf("unconfigured output changed the 0.3.1 enrollment response: digest %s", got)
				}
				if value := send(`{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}`); value["error_code"] != float64(unsupportedCode) {
					t.Fatal("retaining enrollment compatibility enabled an unconfigured output")
				}
			})
		}
	}
}
