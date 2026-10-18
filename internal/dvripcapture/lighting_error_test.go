package dvripcapture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLightingRejectionReportsOnlyMethodStageAndNumericCode(t *testing.T) {
	answer := map[string]any{"error": map[string]any{"code": json.Number("268632079"), "message": "secret-bearing peer message", "password": "private"}, "params": map[string]any{"token": "private"}}
	err := lightingRejection("configManager.setConfig", answer)
	var diagnostic *LightingError
	if !errors.As(err, &diagnostic) || diagnostic.Operation != "configManager.setConfig" || diagnostic.Stage != "rejected" || diagnostic.DeviceCode == nil || *diagnostic.DeviceCode != 268632079 || !errors.Is(err, ErrLightingUnsupported) {
		t.Fatalf("missing structured rejection: %v", err)
	}
	encoded, _ := json.Marshal(diagnostic)
	for _, value := range []string{string(encoded), err.Error()} {
		if strings.Contains(value, "private") || strings.Contains(value, "secret-bearing") {
			t.Fatal("peer error leaked")
		}
	}
	for _, value := range []any{"268632079", json.Number("1.5"), json.Number("999999999999999999999999"), nil} {
		err := lightingRejection("global.logout", map[string]any{"error": map[string]any{"code": value}})
		var failure *LightingError
		errors.As(err, &failure)
		if failure.DeviceCode != nil {
			t.Fatal("unvalidated device code accepted")
		}
	}
}

func TestLightingDiagnosticSurvivesCleanupErrorJoin(t *testing.T) {
	err := errors.Join(lightingFailure("configManager.setConfig", "read_response", nil), ErrLightingRestore, lightingFailure("configManager.getConfig", "restore_reconnect", nil), lightingFailure("global.logout", "session_unavailable", nil))
	if !errors.Is(err, ErrLightingRestore) || !strings.Contains(err.Error(), "restore_reconnect") || !strings.Contains(err.Error(), "global.logout") {
		t.Fatal("cleanup diagnostic discarded")
	}
}
